import yaml

def parse_github_actions_workflow(file_path):
    try:
        with open(file_path, 'r') as file:
            workflow = yaml.safe_load(file)
        return workflow
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def detect_hardcoded_secrets(workflow):
    secrets_found = []
    if workflow is None:
        return secrets_found
    jobs = workflow.get('jobs', {})
    for job_id, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            for key, value in step.items():
                if isinstance(value, str) and 'secret' in value.lower():
                    secrets_found.append((job_id, step))
    return secrets_found

# Example usage
workflow = parse_github_actions_workflow('sample_workflow.yml')
secrets = detect_hardcoded_secrets(workflow)
print('Hardcoded secrets found:', secrets)
