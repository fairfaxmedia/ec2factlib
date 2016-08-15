#!/usr/bin/env ruby

require 'net/http'
require 'net/https'
require 'openssl'
require 'base64'
require 'rexml/document'
# We have enough of a minimal parser to get by without the JSON gem.
# However, if it's available we may as well use it.
begin
  require 'json'
rescue LoadError
end

# Escape URI form components.
# URI.encode_www_form_component doesn't exist on Ruby 1.8, so we fall back to
# URI.encode + gsub
def uri_encode(component)
  if URI.respond_to? :encode_www_form_component
    URI.encode_www_form_component(component)
  else
    URI.encode(component).gsub('=', '%3D').gsub(':', '%3A').gsub('/', '%2F').gsub('+', '%2B')
  end
end

# If the JSON gem was loaded, use JSON.parse otherwise use the inbuilt mini parser
def parse_json_object(input)
  if defined? JSON
    JSON.parse(input)
  else
    json_objparse(input)
  end
end

# A mini parser capable of parsing unnested JSON objects.
# A couple of the http://169.254.169.254/ pages return simple JSON
# in the form of:
# {
#   "KeyA" : "ValueA",
#   "KeyB" : "ValueB"
# }
# Which this should be able to handle. We should still use the JSON library if it's available though
def json_objparse(input)
  input = input.strip # Copy, don't strip! the source string

  unless input.start_with?('{') && input.end_with?('}')
    raise "not an object"
  end

  body = input[1..-2].gsub("\n", ' ') # Easier than dealing with newlines in regexen
  if body.empty?
    return {}
  end
  obj = {}

  until body.nil? || body =~ /^\s*$/
    next if body.match(/^\s*"([^"]*)"\s*:\s*("[^"]*"|\d+\.\d+|\d+|null|true|false)\s*(?:,(.*)|($))/) do |md|
      key      = md[1]
      if obj.has_key? key
        raise "Duplicate key #{key}"
      end

      case md[2]
      when 'null'
        obj[key] = nil
      when 'true'
        obj[key] = true
      when 'false'
        obj[key] = false
      when /^"[^"]*"$/
        obj[key] = md[2][1..-2]
      when /^\d+\.\d+$/
        obj[key] = md[2].to_f
      when /^\d+$/
        obj[key] = md[2].to_i
      end
      body     = md[3]
      true
    end

    raise "Parsing failed at #{body.strip.inspect}"
  end

  obj
end
# The instance document tells us our instance id, region, etc
def get_instance_document
  url = URI.parse('http://169.254.169.254/latest/dynamic/instance-identity/document')
  response = Net::HTTP.get_response(url)

  return nil if response.code != "200"

  return parse_json_object(response.body)
end

# If an IAM role is available for the instance, we will attempt to query it.
# We return an empty Hash on failure. Keys may be available via enviroment
# variables as a fallback.
def get_instance_role
  url = URI.parse('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  response = Net::HTTP.get_response(url)

  return {} if response.code != "200"

  body = response.body

  role = body.lines.first
  response = Net::HTTP::get_response(url+role)

  return {} if response.code != "200"

  role = parse_json_object(response.body)
end

# Sign and send a request to the AWS REST API. Method is defined as an "Action" parameter.
# parameters is an array because order is important for the signing process.
def query(parameters, endpoint, access_key, secret_key, token = nil)
  timestamp = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

  parameters += [
    ['AWSAccessKeyId',    access_key          ],
    ['SignatureVersion',  '2'                 ],
    ['SignatureMethod',   'HmacSHA256'        ],
    ['Timestamp',         timestamp           ],
  ]
  if token
    parameters.push(['SecurityToken', token])
  end

  sorted_parameters    = parameters.sort_by    {|k,v| k }
  sorted_params_string = sorted_parameters.map {|k,v| "#{uri_encode(k)}=#{uri_encode(v)}" }.join('&')
  params_string        = parameters.map        {|k,v| "#{uri_encode(k)}=#{uri_encode(v)}" }.join('&')

  canonical_query = [
    'GET',
    endpoint,
    '/',
    sorted_params_string
  ].join("\n")

  sha256    = OpenSSL::Digest::Digest.new('sha256')
  signature = OpenSSL::HMAC.digest(sha256, secret_key, canonical_query)
  signature = Base64.encode64(signature).strip
  signature = uri_encode(signature)

  req_path = "/?#{params_string}&Signature=#{signature}"

  retries = 5
  begin
    req = Net::HTTP::Get.new(req_path)

    http = Net::HTTP.new(endpoint, 443)
    http.use_ssl = true

    response = http.start { http.request(req) }

    response
  rescue StandardError, Timeout::Error => e
    Facter.debug("Error querying 'http://#{endpoint}/?#{sorted_params_string}' - retries left: #{retries}")
    sleep 3
    retry if (retries -= 1) > 0
  end
end

# Queries CFN endpoint for stack info
def query_cfn(stack_name, endpoint, access_key, secret_key, token = nil)
  parameters = [
    ['Action',            'DescribeStacks' ],
    ['StackName',         stack_name       ],
    ['Version',           '2010-05-15'     ],
  ]
  response = query(parameters, endpoint, access_key, secret_key, token)

  if response.code != "200"
    Facter.debug("DescribeStacks returned #{response.code} #{response.message}")
    return {}
  end

  doc = REXML::Document.new(response.body)

  cfn = {}

  # Stack Parameters
  doc.get_elements('//Parameters/member').each do |item|
    key = item.get_elements('ParameterKey')[0].text
    value = item.get_elements('ParameterValue')[0].text
    cfn['cfn_stack_param_' + key] = value
  end

  return cfn
end

# Queries the tags from the provided EC2 instance id.
def query_instance(instance_id, endpoint, access_key, secret_key, token = nil)
  parameters = [
    ['Action',            'DescribeInstances' ],
    ['InstanceId.1',      instance_id         ],
    ['Version',           '2014-10-01'        ],
  ]
  response = query(parameters, endpoint, access_key, secret_key, token)

  if response.code != "200"
    Facter.debug("DescribeInstances returned #{response.code} #{response.message}")
    return {}
  end

  doc = REXML::Document.new(response.body)

  tags = {}
  doc.get_elements('//tagSet/item').each do |item|
    key = item.get_elements('key')[0].text
    key.gsub!(':','_')
    value = item.get_elements('value')[0].text
    tags["ec2_tag_#{key}"] = value
  end

  lifecycle = doc.get_elements('//instanceLifecycle')[0]
  if ! lifecycle.nil?
    tags['ec2_lifecycle'] = lifecycle.text
  end

  return tags
end

# Queries the min/max/desired size of the provided autoscaling group.
def query_autoscale_group(group_id, endpoint, access_key, secret_key, token)
  parameters = [
    ['Action',                            'DescribeAutoScalingGroups' ],
    ['AutoScalingGroupNames.member.1',    group_id                    ],
    ['Version',                           '2011-01-01'                ],
  ]
  response = query(parameters, endpoint, access_key, secret_key, token)

  if response.code != "200"
    Facter.debug("DescribeAutoScalingGroups returned #{response.code} #{response.message}")
    return {}
  end

  doc = REXML::Document.new(response.body)

  # Note: These params get merged into the facts Hash, so the keys should match the fact names
  params = {}

  min_size_elem = doc.get_elements('//MinSize')[0]
  if min_size_elem.nil?
    Facter.debug("No MinSize found for autoscaling group #{group_id}")
    return nil
  else
    params['autoscaling_min_size'] = min_size_elem.text
  end

  max_size_elem = doc.get_elements('//MaxSize')[0]
  if max_size_elem.nil?
    Facter.debug("No MaxSize found for autoscaling group #{group_id}")
    return nil
  else
    params['autoscaling_max_size'] = max_size_elem.text
  end

  desired_cap_elem = doc.get_elements('//DesiredCapacity')[0]
  if desired_cap_elem.nil?
    Facter.debug("No DesiredCapacity found for autoscaling group #{group_id}")
    return nil
  else
    params['autoscaling_desired_capacity'] = desired_cap_elem.text
  end

  elbs = []
  elb_elem = doc.get_elements('//LoadBalancerNames/member').each do |item|
    elbs << item.text
  end
  if elbs
    params['autoscaling_elbs'] = elbs
  end

  # Get the ASG tags.
  doc.get_elements('//Tags/member').each do |item|
    key = item.get_elements('Key')[0].text
    next if key.start_with?('aws:')
    key.gsub!(':','_')
    value = item.get_elements('Value')[0].text
    params["autoscaling_tag_#{key}"] = value
  end

  return params
end

# Look for our EC2 instance ID, then query the tags assigned to the instance.
# If there is an autoscaling group tag (aws:autoscaling:groupName), also query
# the autoscaling group min/max/desired size parameters.
def check_facts

  cache_file = '/tmp/ec2_facts.json'
  if File.exist?(cache_file)
    if ( ( Time.now - File.stat(cache_file).mtime ).to_i < [ 43200, 86400 ].sample )
      Facter.debug( "reading from cache: " + cache_file  )
      open(cache_file, 'r') do |io|
        facts = parse_json_object(io.read.strip)
        facts.each do |fact, value|
          Facter.add(fact) do
            setcode { value }
          end
        end
      end
      return
    end
  end

  facts = {}
  if File.exists?('/etc/ec2_version')
    open('/etc/ec2_version', 'r') do |io|
      facts['ec2_version'] = io.read.strip
    end
  end

  instance    = get_instance_document
  if instance.nil?
    Facter.debug("Didn't get instance document from http://169.254.169.254/latest/dynamic/instance-identity/document")
    return
  end

  instance_id = instance['instanceId']
  region      = instance['region']
  role        = get_instance_role

  access_key  = role['AccessKeyId']     || ENV['AWS_ACCESS_KEY_ID']
  secret_key  = role['SecretAccessKey'] || ENV['AWS_SECRET_ACCESS_KEY']
  token       = role['Token']

  if access_key.nil? || secret_key.nil?
    Facter.debug("No authentication key available")
    return
  end

  tags = query_instance(instance_id, "ec2.#{region}.amazonaws.com", access_key, secret_key, token)
  tags.each do |tag, value|
    facts[tag] = value
  end

  if tags.has_key? 'ec2_tag_aws_autoscaling_groupName'

    autoscale_group = tags['ec2_tag_aws_autoscaling_groupName']

    facts['autoscaling_group_name'] = autoscale_group

    asg_params = query_autoscale_group(autoscale_group, "autoscaling.#{region}.amazonaws.com", access_key, secret_key, token)
    facts = facts.merge(asg_params)
  end

  if tags.has_key? 'aws:cloudformation:stack-name'
    cfn_stack_name = tags['aws:cloudformation:stack-name']
    facts['cloudformation_stack_name'] = cfn_stack_name

    # Grab CFN parameters
    cfn_data = query_cfn(cfn_stack_name, "cloudformation.#{region}.amazonaws.com", access_key, secret_key, token)
    facts = facts.merge(cfn_data)
  end

  File.open(cache_file, "w", 0644) { |f| f.write(facts.to_json) }

  facts.each do |fact, value|
    Facter.add(fact) do
      setcode { value }
    end
  end
rescue StandardError => e
  Facter.debug("Unhandled #{e.class}: #{e.message}")
end

# We mostly want to avoid waiting for http://169.254.169.254/ to time out if we are not on EC2.
# This only checks if we are a guest, not if we are on ec2.
if File.exists?('/sys/hypervisor/uuid')
  # check contents of uuid, starts with ec2
  f=open('/sys/hypervisor/uuid')
  if f.read[0..2] == 'ec2'
    check_facts
  end
  f.close
end
