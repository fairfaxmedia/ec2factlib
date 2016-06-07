# ec2factlib - EC2 Facts library

A puppet/facter plugin to expose EC2 instance details as facts.

The plugin is written in (almost\*) vanilla/stdlib ruby to make it suitable for
initial bootstrap without the aws-sdk gem installed.

\* Has a soft dependency on the json gem. At the time of writing, it can get by
with a builtin mini parser but `JSON.parse` will be used if available.

Facts currently include:
* EC2 version string from `/etc/ec2_version` (`ec2_version`)
* EC2 instance tags (`ec2_tag_*`)
* CloudFormation stack name (`cloudformation_stack_name`)
* CloudFormation stack parameters (`cfn_stack_param_*`)
* Autoscaling group name (`autoscaling_group_name`)
* Autoscaling group min/max/desired size (`autoscaling_(min|max)_size`, `autoscaling_desired_capacity`)
* Autoscaling group ELBs (`autoscaling_elb`)
* Autoscaling group tags (`autoscaling_tag_*`)
* Lifecycle (spot) (`ec2_lifecycle`)

The facts are cached in `/tmp/ec2_facts.json` to save on excessive AWS API lookups.

TODO: Currently uses the simpler v2 signing process for REST API requests. This
should be updated to the v4 signing process.
