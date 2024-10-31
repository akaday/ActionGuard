# ActionGuard

ActionGuard is a tool designed to enhance the security of GitHub Actions workflows by detecting potential security issues such as hardcoded secrets, deprecated actions, and insecure configurations.
## Support ENGINEER AUTOMATION EMBEDDED SYSTEMS 

IM GRATEFULL , consider buying me a coffee! Your support is greatly appreciated.

[![Buy Me a Coffee](https://img.shields.io/badge/Donate-Buy%20Me%20a%20Coffee-yellow)](https://paypal.me/barki0)

 Features:

- **Detection of Hardcoded Secrets**: Identifies hardcoded secrets in workflows.
- **Detection of Deprecated Actions**: Flags the use of deprecated or insecure actions.
- **Comprehensive Security Checks**: Scans for misconfigurations and permissions issues.
- **User-Friendly Reporting**: Generates detailed reports of detected issues.

## Getting Started

### Prerequisites

- **Python 3.x**: Ensure that Python is installed on your system.
  ```bash
  python --version
Installation
Clone the Repository:

bash
git clone https://github.com/akaday/ActionGuard.git
cd ActionGuard
Install Dependencies:

bash
pip install -r requirements.txt
Usage
Run the Script:

bash
python test_script.py
Example Output:

plaintext
Hardcoded secrets found:
- Job: build, Step: {'name': 'Hardcoded secret', 'run': 'echo "SECRET_API_KEY=1234567890"'}
Deprecated actions found:
- Job: build, Step: {'uses': 'actions/setup-python@v1'}
Expanding Functionality
Detect Insecure Actions:

python
def detect_insecure_actions(workflow):
    insecure_actions = ['actions/setup-python@v1', 'actions/checkout@v1']
    actions_found = []
    if workflow is None:
        return actions_found
    jobs = workflow.get('jobs', {})
    for job_id, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            if 'uses' in step and step['uses'] in insecure_actions:
                actions_found.append((job_id, step))
    return actions_found
Improve Reporting:

python
def generate_report(secrets, deprecated_actions):
    report = []
    if secrets:
        report.append("Hardcoded secrets found:")
        for job_id, step in secrets:
            report.append(f"  - Job: {job_id}, Step: {step}")

    if deprecated_actions:
        report.append("Deprecated actions found:")
        for job_id, step in deprecated_actions:
            report.append(f"  - Job: {job_id}, Step: {step}")
    
    return "\n".join(report)
Contributing
Contributions are welcome! Please submit a pull request or open an issue to get started.

License
This project is licensed under the MIT License.

Support
If you find this project helpful, consider buying me a coffee! Your support is greatly appreciated.


Happy coding with ActionGuard! 😊🚀✨


You can copy this content into your `README.md` file to ensure it provides clear and helpful information about your project.

If you need any further assistance or have any questions, feel free to ask! 😊🚀✨

Happy coding with ActionGuard! 🎉🛡️✨
