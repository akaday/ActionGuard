import yaml
import json
import os

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

# Example usage with non-vulnerable workflow
workflow = parse_github_actions_workflow('sample_workflow.yml')
advisories = load_advisory_database('advisory-database/advisories')
vulnerabilities = detect_known_vulnerabilities(workflow, advisories)
print('Known vulnerabilities found:', vulnerabilities)

# Example usage with vulnerable workflow
vulnerable_workflow = parse_github_actions_workflow('vulnerable_workflow.yml')
vulnerabilities_in_vulnerable_workflow = detect_known_vulnerabilities(vulnerable_workflow, advisories)
print('Known vulnerabilities found in vulnerable workflow:', vulnerabilities_in_vulnerable_workflow)
