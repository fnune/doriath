#!/bin/sh
PATH=/run/doriath-bin:$PATH
doriath describe "Review the Terraform plan for the staging cluster" >/dev/null
curl -sS -m 300 -o /dev/null https://registry.terraform.io/v1/providers/hashicorp/aws/versions 2>/dev/null &
sleep 0.4
doriath request open https://console.aws.amazon.com/eks/home --reason "Show the cluster that the plan changes" >/dev/null
sleep 600
