name: CI with Security Checks

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v2

    - name: Set up Python
      uses: actions/setup-python@v2

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt

    - name: Run security checks
      run: |
        python test_script.py

    - name: Check advisory database for known vulnerabilities
      run: |
        python -c "
        import yaml;
        import os;

        def load_advisory_database(path):
            advisories = [];
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith('.yaml'):
                        with open(os.path.join(root, file), 'r') as f:
                            advisory = yaml.safe_load(f);
                            advisories.append(advisory);
            return advisories;

        def detect_known_vulnerabilities(workflow, advisories):
            vulnerabilities_found = [];
            jobs = workflow.get('jobs', {});
            for job_id, job in jobs.items():
                steps = job.get('steps', []);
                for step in steps:
                    if 'uses' in step:
                        action = step['uses'];
                        for advisory in advisories:
                            if action in advisory.get('affected', []):
                                vulnerabilities_found.append((job_id, step, advisory));
            return vulnerabilities_found;

        def parse_github_actions_workflow(file_path):
            try:
                with open(file_path, 'r') as file:
                    workflow = yaml.safe_load(file);
                return workflow;
            except FileNotFoundError:
                print(f'File not found: {file_path}');
                return None;

        workflow = parse_github_actions_workflow('sample_workflow.yml');
        advisories = load_advisory_database('advisory-database');
        vulnerabilities = detect_known_vulnerabilities(workflow, advisories);
        print('Known vulnerabilities found:', vulnerabilities);
        "
