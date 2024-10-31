# Example usage with vulnerable workflow
vulnerable_workflow = parse_github_actions_workflow('vulnerable_workflow.yml')
vulnerabilities_in_vulnerable_workflow = detect_known_vulnerabilities(vulnerable_workflow, advisories)
print('Known vulnerabilities found in vulnerable workflow:', vulnerabilities_in_vulnerable_workflow)
