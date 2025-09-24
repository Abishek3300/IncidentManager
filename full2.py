import time
from datetime import datetime, timedelta, timezone
import boto3
import shlex
from strands import Agent, tool
from strands.models import BedrockModel
import re
import functools

# ---------------- CONFIGURATION ----------------
REGION = "ap-south-1"
INSTANCE_ID = "i-0bb4262df055138b2"

ssm_client = boto3.client("ssm", region_name=REGION)
cloudwatch_client = boto3.client("cloudwatch", region_name=REGION)

# ---------------- AGENT SETUP ----------------
system_prompt = """
<role>
You are a specialized AWS Infrastructure Monitoring and Optimization Agent that analyzes EC2 and DynamoDB metrics/logs to detect issues and provide optimization recommendations.
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
    <dynamodb>ThrottledRequests, Read/WriteThrottleEvents, ConsumedCapacity, Errors</dynamodb>
  </metrics>
  <todo>
  <rule>For the given time period, analyze when the cpu spike is highest and correlate the logs in that minute and give the reason</rule>
  </todo>

  <logs>
    <types>Access logs, error logs, system logs, gunicorn logs</types>
    <priority_rules>
      <rule>Always analyze error log entries, system log errors, and gunicorn logs even if metrics are normal</rule>
    </priority_rules>
  </logs>
</analysis_requirements>

<thresholds>
  <cpu alert="60%" critical="90%" />
  <memory alert="45%" critical="65%" />
  <disk alert="75%" critical="95%" />
  <network_in alert="3.1MB" critical="6.2MB" />
  <network_out alert="18MB" critical="36MB" />
  <dynamodb_throttling alert="5%" critical="15%" />
</thresholds>
<considerations>
<rule>Do not consider the traffic as automated attact</rule>
</considerations>
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

monitor_agent = Agent(name="MonitorAgent", system_prompt=system_prompt, model=model)

# ---------------- DECORATOR FOR TIMING ----------------
def time_it(func):
    """Decorator to measure and print the execution time of a function."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"⌛ Execution time of '{func.__name__}': {end_time - start_time:.4f} seconds")
        return result
    return wrapper

# ---------------- FUNCTIONS ----------------

@time_it
  
def get_ec2_status(instance_id: str):
    """
    Get the current operational status of an EC2 instance.
    Args:
        instance_id (str): The ID of the EC2 instance.
    Returns:
        tuple: A tuple containing the state, system status, and instance status.
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

@time_it 
def get_cpu_per_minute(instance_id: str, start_time: datetime, end_time: datetime):
    """
    Fetch CPU utilization metrics per minute from CloudWatch.
    Args:
        instance_id (str): The ID of the EC2 instance.
        start_time (datetime): The start of the time window.
        end_time (datetime): The end of the time window.
    Returns:
        list: A list of dictionaries with timestamp and CPU usage.
    """
    try:
        resp = cloudwatch_client.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=60,
            Statistics=["Average"],
            Unit="Percent"
        )

        points = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
        return [{"Timestamp": dp["Timestamp"], "CPU": dp["Average"]} for dp in points]
    except Exception as e:
        print(f"Error fetching CPU metrics: {e}")
        return []

@time_it
def get_all_gunicorn_sites(instance_id: str):
    """
    Find all running Gunicorn websites and their access log paths efficiently.

    Args:
        instance_id (str): The ID of the EC2 instance.
    Returns:
        list: A list of dictionaries with site name and log path.
    """
    cmd = "ps aux | grep gunicorn | grep -v 'grep'"
    
    # Send a single SSM command to get the list of processes
    try:
        res = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [cmd]},
            TimeoutSeconds=60
        )
        cmd_id = res['Command']['CommandId']
        time.sleep(2)
        
        # Poll for command status until it's complete
        status = ''
        while status not in ['Success', 'Failed', 'Cancelled']:
            time.sleep(1)
            output = ssm_client.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            status = output['Status']

        if status == 'Success':
            processes = output.get("StandardOutputContent", "").strip().splitlines()
        else:
            print(f"SSM Command Failed: {output.get('StandardErrorContent', '')}")
            processes = []
    except Exception as e:
        print(f"Error executing SSM command: {e}")
        processes = []
    
    sites = []
    # Regex to capture the site name from the .sock file and the log path
    log_path_regex = re.compile(r'/var/www/(?P<site_name>.*?)/\S*\.sock.*?--access-logfile (?P<access_log>\S+)')

    for line in processes:
        match = log_path_regex.search(line)
        if match:
            site_name = match.group('site_name')
            access_log = match.group('access_log')
            
            # Assume log path is relative if not absolute
            if not access_log.startswith('/'):
                access_log = f"/var/www/{site_name}/logs/{access_log}"

            sites.append({
                "site_name": site_name,
                "access_log_path": access_log
            })
    return sites

@time_it 
def get_log_counts_for_sites(instance_id: str, sites: list, spike_time: datetime):
    """
    Get access log counts for each site for pre-spike (10 mins), spike-time (1 min), 
    and post-spike (10 mins) windows.
    
    Args:
        instance_id (str): EC2 instance ID.
        sites (list): List of dicts with 'site_name' and 'access_log_path'.
        spike_time (datetime): Timestamp of CPU spike.
        
    Returns:
        dict: log counts per site: {'before': X, 'spike': Y, 'after': Z}
    """
    log_counts = {site['site_name']: {'before': 0, 'spike': 0, 'after': 0} for site in sites}

    def count_logs(site, start_time, end_time):
        start_str = start_time.strftime("%d/%b/%Y:%H:%M:%S")
        end_str = end_time.strftime("%d/%b/%Y:%H:%M:%S")

        cmd = f"awk -v start='{start_str}' -v end='{end_str}' '{{ t = substr($4, 2, 19); if (t >= start && t <= end) print }}' {site['access_log_path']} | wc -l"

        try:
            res = ssm_client.send_command(
                InstanceIds=[INSTANCE_ID],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [cmd]},
                TimeoutSeconds=60
            )
            cmd_id = res['Command']['CommandId']
            time.sleep(2)
            output = ssm_client.get_command_invocation(CommandId=cmd_id, InstanceId=INSTANCE_ID)
            return int(output.get("StandardOutputContent", "0").strip() or 0)
        except Exception as e:
            print(f"Error counting logs for {site['site_name']}: {e}")
            return 0

    # Define windows
    pre_spike_start = spike_time - timedelta(minutes=10)
    pre_spike_end = spike_time - timedelta(seconds=1)  # 1 second before spike
    spike_start = spike_time
    spike_end = spike_time + timedelta(minutes=1) - timedelta(seconds=1)  # full spike minute
    post_spike_start = spike_time + timedelta(minutes=1)  # start after spike minute
    post_spike_end = spike_time + timedelta(minutes=11)   # 10 minutes after spike

    # Pre-spike counts
    for site in sites:
        log_counts[site['site_name']]['before'] = count_logs(site, pre_spike_start, pre_spike_end)

    # Spike counts
    for site in sites:
        log_counts[site['site_name']]['spike'] = count_logs(site, spike_start, spike_end)

    # Post-spike counts
    for site in sites:
        log_counts[site['site_name']]['after'] = count_logs(site, post_spike_start, post_spike_end)

    return log_counts

@time_it  
def fetch_logs_window(instance_id: str, log_path: str, start_time: datetime, end_time: datetime):
    """
    Fetch all log entries from a file within a specific time window using a single command.
    Args:
        instance_id (str): The ID of the EC2 instance.
        log_path (str): The full path to the log file.
        start_time (datetime): The start of the time window.
        end_time (datetime): The end of the time window.
    Returns:
        str: A string of log entries, or an error message.
    """
    start_str = start_time.strftime("%d/%b/%Y:%H:%M:%S")
    end_str = end_time.strftime("%d/%b/%Y:%H:%M:%S")
    

    # Use awk to filter logs in a single command
    cmd = (
    f"awk -v start='{start_str}' -v end='{end_str}' '{{ "
    f"t = substr($4, 2, 20); "  # <-- use 20, includes seconds
    f"if (t >= start && t <= end) print "
    f"}}' {log_path} || echo 'No logs found in the window.'"
)

    try:
        res = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [cmd]},
            TimeoutSeconds=60
        )
        cmd_id = res['Command']['CommandId']
        time.sleep(2)
        output = ssm_client.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        logs = output.get("StandardOutputContent", "").strip()
        return logs if logs else "No logs found in the window."
    except Exception as e:
        return f"Error fetching logs: {e}"

# ---------------- MONITORING LOOP ----------------

print("🌐 Started Monitoring...")

while True:
    try:
        # Step 1: Get EC2 status and CPU metrics
        state, system_status, instance_status = get_ec2_status(INSTANCE_ID)
        now_utc = datetime.now(timezone.utc)
        one_hour_ago = now_utc - timedelta(hours=1)
        
        cpu_per_minute = get_cpu_per_minute(INSTANCE_ID, start_time=one_hour_ago, end_time=now_utc)
        
        print("\n--- Current EC2 Status ---")
        print(f"EC2 State: {state}")
        print(f"System Status: {system_status}")
        print(f"Instance Status: {instance_status}")

        print("\n--- CPU Utilization Per Minute (Last Hour) ---")
        if not cpu_per_minute:
            print("No CPU data found in the last hour.")
            report = "" # Initialize report to an empty string if no data is found.
        else:
            for dp in cpu_per_minute:
                print(f"{dp['Timestamp']} - {dp['CPU']:.2f}% CPU")

            # Step 2: Detect the highest CPU spike and define the analysis windows
            spike = max(cpu_per_minute, key=lambda x: x["CPU"])
            spike_time = spike["Timestamp"]
            spike_value = spike["CPU"]
            
            print(f"\n--- CPU Spike Analysis ---")
            print(f"🚨 Highest CPU spike detected at {spike_time} with {spike_value:.2f}% utilization.")
            
            pre_spike_start_window = spike_time - timedelta(minutes=10)
            pre_spike_end_window = spike_time
            post_spike_start_window = spike_time
            post_spike_end_window = spike_time + timedelta(minutes=10)
            
            print(f"Pre-spike analysis window: {pre_spike_start_window} to {pre_spike_end_window}")
            print(f"Post-spike analysis window: {post_spike_start_window} to {post_spike_end_window}")

            # Step 3: Get all Gunicorn sites and their log counts for both windows
            all_sites = get_all_gunicorn_sites(INSTANCE_ID)

            if not all_sites:
                print("\nNo Gunicorn sites found running.")
                report = ""
            else:
                log_counts = get_log_counts_for_sites(INSTANCE_ID, all_sites, spike_time)





                print("\n--- Access Log Counts ---")
                report_metrics = []

                # Find the site with the maximum spike
    #             Spike_site, max_diff = max(
    # ((site, abs(counts['after'] - counts['before'])) for site, counts in log_counts.items()),
    # key=lambda x: x[1],
    # default=(None, 0)
# )
                Spike_site = None
                max_spike = 0
                for site, counts in log_counts.items():
                    before_count = counts.get('before', 0)
                    spike_count = counts.get('spike', 0)
                    after_count = counts.get('after', 0)

                    # Compute ALL pairwise differences
                    diff_before_spike = abs(spike_count - before_count)
                    diff_spike_after = abs(after_count - spike_count)
                    diff_before_after = abs(after_count - before_count)

                    # Take the largest difference as the site's "spike magnitude"
                    site_spike = max(diff_before_spike, diff_spike_after, diff_before_after)

                    if site_spike > max_spike:
                        max_spike = site_spike
                        Spike_site = site

                    print(f"Website: {site}")
                    print(f"  - Before Spike: {before_count} requests")
                    print(f"  - At Spike: {spike_count} requests")
                    print(f"  - After Spike: {after_count} requests")
                    print(f"  - Spike Magnitude: {site_spike} requests")

                    report_metrics.append(
                        f"  - Website: {site}, Before Spike: {before_count}, At Spike: {spike_count}, "
                        f"After Spike: {after_count}, Spike Magnitude: {site_spike}"
                    )
                # Get log path for the spiked site
                # Get log path
                Spike_log_path = next(
                        (s['access_log_path'] for s in all_sites if s['site_name'] == Spike_site),
                        None
                    )



                report = f"""
EC2 Status: {state}
System Status: {system_status}
Instance Status: {instance_status}
CPU Utilization Per Minute (Last Hour):
"""
                for dp in cpu_per_minute:
                    report += f"{dp['Timestamp']} - {dp['CPU']:.2f}% CPU\n"

                report += f"\n🚨 Highest CPU spike detected at {spike_time} with {spike_value:.2f}% utilization.\n"
                report += f"\n📊 Access log counts analysis for the spike window:\n" + "\n".join(report_metrics)
                
                if Spike_site and Spike_log_path:
                    print(f"\n--- Spike Identified ---")
                    print(f"🕵️‍♂️ Website with the most significant spike in requests: {Spike_site} with an difference of {max_spike} requests.")

                    report += f"\n🕵️‍♂️ Website with the most significant spike in requests: {Spike_site} with an increase of {max_spike} requests.\n"

                    # Step 5: Fetch logs for the Spike site in the analysis window
                    logs_from_Spike = fetch_logs_window(INSTANCE_ID, Spike_log_path, pre_spike_start_window, post_spike_end_window)
                    report += f"\n📜 Detailed logs for {Spike_site} during the spike:\n{logs_from_Spike}\n"
                    print(f"\n--- Detailed Logs for {Spike_site} ---\n{logs_from_Spike}")
                else:
                    report += "\nCould not identify a clear Spike website from log data.\n"
                    print("\nCould not identify a clear Spike website from log data.")
        
        # Step 6: Send the report to the agent for analysis
        print("\n--- Sending to Agent ---")
        print("Sending the generated report to the AI agent for root cause analysis and recommendations...")
        try:
            result = monitor_agent(f"Analyze the following metrics and provide a root cause analysis with recommended actions:\n{report}")
            # print("\nAGENT RESPONSE:\n", result)
        except Exception as e:
            print(f"Error analyzing report with agent: {e}")

    except Exception as e:
        print(f"An error occurred in the main monitoring loop: {e}")
    
    print("---------------------------------------------------")
    time.sleep(60)
