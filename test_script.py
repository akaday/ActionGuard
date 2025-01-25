import yaml
import json
import os
import requests

def parse_github_actions_workflow(file_path):
    try:
        with open(file_path, 'r') as file:
            workflow = yaml.safe_load(file)
        return workflow
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def load_advisory_database(path):
    advisories = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                print(f"Reading advisory file: {file_path}")
                with open(file_path, 'r', encoding='utf-8') as f:
                    advisory = json.load(f)
                    advisories.append(advisory)
    print(f"Loaded {len(advisories)} advisories.")
    if advisories:
        print(f"Sample advisory: {advisories[0]}")
    return advisories

def detect_known_vulnerabilities(workflow, advisories):
    vulnerabilities_found = []
    jobs = workflow.get('jobs', {})
    for job_id, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            if 'uses' in step:
                action = step['uses']
                print(f"Checking action: {action}")
                for advisory in advisories:
                    if action in advisory.get('affected', []):
                        vulnerabilities_found.append((job_id, step, advisory))
    return vulnerabilities_found

# List of deprecated actions
deprecated_actions = [
    'actions/setup-python@v1',
    'actions/checkout@v1'
]

def detect_deprecated_actions(workflow):
    deprecated_actions_found = []
    jobs = workflow.get('jobs', {})
    for job_id, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            if 'uses' in step:
                action = step['uses']
                if action in deprecated_actions:
                    deprecated_actions_found.append((job_id, step))
    return deprecated_actions_found

def get_latest_action_version(action):
    response = requests.get(f'https://api.github.com/repos/{action}/releases/latest')
    if response.status_code == 200:
        latest_version = response.json().get('tag_name')
        return latest_version
    return None

def compare_action_versions(workflow):
    version_issues = []
    jobs = workflow.get('jobs', {})
    for job_id, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            if 'uses' in step:
                action = step['uses']
                action_name, action_version = action.split('@')
                latest_version = get_latest_action_version(action_name)
                if latest_version and action_version != latest_version:
                    version_issues.append((job_id, step, latest_version))
    return version_issues

def update_deprecated_actions_list():
    response = requests.get('https://example.com/deprecated-actions-list')
    if response.status_code == 200:
        global deprecated_actions
        deprecated_actions = response.json().get('deprecated_actions', deprecated_actions)

def detect_insecure_configurations(workflow):
    insecure_configurations = []
    jobs = workflow.get('jobs', {})
    for job_id, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            if 'run' in step:
                run_command = step['run']
                if 'sudo' in run_command or 'curl' in run_command:
                    insecure_configurations.append((job_id, step))
    return insecure_configurations

# Example usage with non-vulnerable workflow
workflow = parse_github_actions_workflow('sample_workflow.yml')
advisories = load_advisory_database('advisory-database/advisories')
vulnerabilities = detect_known_vulnerabilities(workflow, advisories)
print('Known vulnerabilities found:', vulnerabilities)

# Example usage with vulnerable workflow
vulnerable_workflow = parse_github_actions_workflow('vulnerable_workflow.yml')
vulnerabilities_in_vulnerable_workflow = detect_known_vulnerabilities(vulnerable_workflow, advisories)
print('Known vulnerabilities found in vulnerable workflow:', vulnerabilities_in_vulnerable_workflow)

# Detect deprecated actions
deprecated_actions_found = detect_deprecated_actions(workflow)
print('Deprecated actions found:', deprecated_actions_found)

# Compare action versions
version_issues = compare_action_versions(workflow)
print('Version issues found:', version_issues)

# Update deprecated actions list
update_deprecated_actions_list()
print('Updated deprecated actions list:', deprecated_actions)

# Detect insecure configurations
insecure_configurations_found = detect_insecure_configurations(workflow)
print('Insecure configurations found:', insecure_configurations_found)
