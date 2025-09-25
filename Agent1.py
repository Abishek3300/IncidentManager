import time
from datetime import datetime, timedelta, timezone
import boto3
import shlex
from strands import Agent, tool
from strands.models import BedrockModel
import re
import functools
import os
from typing import List, Dict

# ---------------- CONFIGURATION ----------------
REGION = "ap-south-1"
INSTANCE_ID = "i-0bb4262df055138b2"

ssm_client = boto3.client("ssm", region_name=REGION)
cloudwatch_client = boto3.client("cloudwatch", region_name=REGION)

# ---------------- AGENT SETUP ----------------
system_prompt = """
<role>
You are a specialized AWS Infrastructure Monitoring and Optimization Agent that analyzes EC2 instance metrics and logs to detect issues and provide optimization recommendations.
</role>

<infrastructure>
  <ec2_configuration>
    <purpose>Hosting e-commerce website</purpose>
    <instance_type>t2.micro</instance_type>
    <vcpus>1</vcpus>
    <memory>1GB</memory>
    <os>Linux</os>
  </ec2_configuration>
</infrastructure>

<analysis_requirements>
  <metrics>
    <ec2>CPU, Memory, Disk, NetworkIn, NetworkOut</ec2>
  </metrics>

  <logs>
    <types>Access logs, error logs, system logs, gunicorn logs</types>
    <priority_rules>
      <rule>Always analyze error log entries, system log errors, and gunicorn logs even if metrics are normal</rule>
    </priority_rules>
  </logs>
</analysis_requirements>
<procedure>
    <step order="1">
        <action>Retrieve the operational status of the EC2 instance.</action>
        <details>
            <metrics>state, system_status, instance_status</metrics>
            <tool>get_ec2_status</tool>
            <note>Use the provided EC2 instance ID.</note>
        </details>
    </step>

    <step order="2">
    <action>Fetch per-minute CPU and Memory utilization for the last 1 hour for the EC2 instance.</action>
    <tool>get_metric</tool>
    <details>
        <metrics>
            <metric>
                <name>CPUUtilization</name>
                <namespace>AWS/EC2</namespace>
                <label>CPU</label>
            </metric>
            <metric>
                <name>mem_used_percent</name>
                <namespace>CWAgent</namespace>
                <label>Memory</label>
            </metric>
        </metrics>
        <start_time>One hour ago in UTC</start_time>
        <end_time>Current time minus 1 minute UTC</end_time>
        <note>Return per-minute data and identify the highest CPU and Memory spikes along with their timestamps.</note>
    </details>
</step>


    <step order="3">
        <action>Identify Unknown or suspicious processes running .</action>
        <action>Use this tool to execute the command to query about the current consumptions of cpu and memory.</action>
        <tool>execute_ssm_command</tool>
        <details>
            <output>Return as raw string only</output>
        </details>

        <forbidden_commands>
          - Any command that deletes or modifies system files (e.g., rm, mv, dd)
        </forbidden_commands>
    </step>

    <step order="4">
        <action>Analyze Gunicorn processes and identify each website's access and error log paths.</action>
        <tool>execute_ssm_command</tool>
        <details>
            <logic>
                - Extract site names
                - Determine log paths dynamically
                - Associate log paths with each site
            </logic>
        </details>
    </step>

    <step order="5">
        <action>For each identified website, count access log entries around the CPU spike minute.</action>
        <tool>execute_ssm_command</tool>
        <details>
            <window>
                <pre_spike>10 minutes before spike</pre_spike>
                <spike>1 minute of spike</spike>
                <post_spike>10 minutes after spike</post_spike>
            </window>
            <note>Return counts for before, during, and after spike.</note>
        </details>
    </step>

    <step order="6">
        <action>Identify the website with the most significant spike in traffic.</action>
        <logic>
            <method>
                - Calculate baseline = (before + after)/2
                - Determine spike jump 
                - Choose site with maximum spike jump
            </method>
        </logic>
    </step>

    <step order="7">
        <action>Fetch detailed logs for the spike site in the analysis window.</action>
        <tool>execute_ssm_command</tool>
        <details>
            <start_time>10 minutes before spike</start_time>
            <end_time>10 minutes after spike</end_time>
        </details>
    </step>

    <step order="8">
        <action>Generate a full report summarizing:</action>
        <details>
            <metrics>EC2 status, CPU & Memory per-minute metrics, identified spike site</metrics>
            <log_analysis>Access log counts and detailed spike logs</log_analysis>
            <output_format>
                ISSUE DETECTED: [ALERT/CRITICAL]
                Service: [EC2/DynamoDB] | Resource: [ID/Name]
                Metric: [Name] = [Value] (Threshold: [Limit])
                ROOT CAUSE: Identify primary root cause.
                RECOMMENDED ACTIONS: 1. Immediate critical action 2. Stabilization step
            </output_format>
        </details>
    </step>


</procedure>


<thresholds>
  <cpu alert="60%" critical="90%" />
  <memory alert="45%" critical="65%" />
  <disk alert="75%" critical="95%" />
  <network_in alert="3.1MB" critical="6.2MB" />
  <network_out alert="18MB" critical="36MB" />
  <dynamodb_throttling alert="5%" critical="15%" />
</thresholds>
<output_format>
ISSUE DETECTED: [ALERT/CRITICAL]
Service: [EC2/DynamoDB] | Resource: [ID/Name]
Metric: [Name] = [Value] (Threshold: [Limit])

ROOT CAUSE:
Identify the primary root cause of the alert.

RECOMMENDED ACTIONS:
1. [Immediate critical action]
2. [Stabilization step]
</output_format>
"""

model = BedrockModel(
    model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
    temperature=0.3,
    region_name="us-east-1"
)



@tool
def get_utc_times(period_hours: int = 1, offset_minutes: int = 1):
    """
    Provides start and end UTC times for metric/log analysis.

    Args:
        period_hours (int): How many hours back to start (default 1 hour).
        offset_minutes (int): Offset from current UTC to avoid partial data (default 1 min).

    Returns:
        dict: {
            "start_time": datetime in UTC,
            "end_time": datetime in UTC
        }
    """
    from datetime import datetime, timezone, timedelta
    end_time = datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)
    start_time = end_time - timedelta(hours=period_hours)
    return {"start_time": start_time, "end_time": end_time}


@tool
def get_ec2_status(instance_id: str):
    """
    Retrieve the operational status of a specific EC2 instance.

    Args:
        instance_id (str): The unique identifier of the EC2 instance.

    Returns:
        tuple: (state, system_status, instance_status)
            - state (str): The current state of the instance (e.g., 'running', 'stopped').
            - system_status (str): The health status of the underlying system hardware.
            - instance_status (str): The health status of the EC2 instance.

    Notes:
        - Handles exceptions and returns 'unknown' if API calls fail.
        - Uses boto3 EC2 client to fetch both instance state and health status.
    """
     
    ec2_client = boto3.client("ec2", region_name=REGION)
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        state = response["Reservations"][0]["Instances"][0]["State"]["Name"]

        status_response = ec2_client.describe_instance_status(InstanceIds=[instance_id])
        if status_response["InstanceStatuses"]:
            system_status = status_response["InstanceStatuses"][0]["SystemStatus"]["Status"]
            instance_status = status_response["InstanceStatuses"][0]["InstanceStatus"]["Status"]
        else:
            system_status = instance_status = "unknown"

        return state, system_status, instance_status
    except Exception as e:
        print(f"Error fetching EC2 status: {e}")
        return "unknown", "unknown", "unknown"

 
@tool
def execute_ssm_command(instance_id: str, command: str) -> str:
    """
    Execute any shell command on an EC2 instance via SSM.

    Args:
        instance_id (str): The EC2 instance ID.
        command (str): Shell command provided by the agent.

    Returns:
        str: Raw command output (stdout or error).
    """
    try:
        print("\nAgent command: ",command)
        # Send the command
        res = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=60
        )
        cmd_id = res['Command']['CommandId']

        # Wait for command to finish
        status = ""
        while status not in ["Success", "Failed", "Cancelled"]:
            time.sleep(1)
            output = ssm_client.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            status = output['Status']
        print("\nSSM RESULT: ",output.get("StandardOutputContent", "").strip() or "No output returned")
        return output.get("StandardOutputContent", "").strip() or "No output returned"
    
    except Exception as e:
        return f"Error executing command: {e}"


@tool
def get_metric(instance_id: str, start_time: datetime, end_time: datetime, metric_name: str, namespace: str, label: str) -> List[Dict]:
    """
    Fetch per-minute metrics for an EC2 instance.

    Args:
        instance_id: EC2 instance ID
        start_time: start datetime
        end_time: end datetime
        metric_name: CloudWatch metric name (e.g., "CPUUtilization", "mem_used_percent")
        namespace: CloudWatch namespace (e.g., "AWS/EC2", "CWAgent")
        label: key to use for the value in returned dict (e.g., "CPU", "Memory")

    Returns:
        List of dicts: [{'Timestamp': datetime, '<label>': value}, ...]
    """
    try:
        resp = cloudwatch_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=60,
            Statistics=["Average"]
        )
        points = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
        return [{"Timestamp": dp["Timestamp"], label: dp["Average"]} for dp in points]
    except Exception as e:
        print(f"Error fetching {metric_name}: {e}")
        return []

print("🌐 Started Monitoring...")

while True:
    try:

        tools = [ execute_ssm_command,get_utc_times,get_ec2_status,get_metric]

        monitor_agent = Agent(name="MonitorAgent", system_prompt=system_prompt, model=model,tools=tools)

        result = monitor_agent(f"The instance id is {INSTANCE_ID} . Analyze the ec2 instance from the available tools and tell the issue and root cause: ")
        # print("\nAGENT RESPONSE:\n", result)
        
    except Exception as e:
        print(f"An error occurred in the main monitoring loop: {e}")
    
    print("---------------------------------------------------")
    time.sleep(60)
