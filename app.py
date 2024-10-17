from flask import Flask, render_template, request
import subprocess
import json

app = Flask(__name__)

# Namespace where Trivy is installed
NAMESPACE = 'alti-chatbot'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_images():
    results = {}

    # Get all pods in the specified namespace
    pods_cmd = f"kubectl get pods -n {NAMESPACE} -o json"
    pods_result = subprocess.run(pods_cmd, shell=True, capture_output=True, text=True)

    if pods_result.returncode != 0:
        return render_template('results.html', results={"error": pods_result.stderr})

    # Parse the JSON output to get container images
    try:
        pods_data = json.loads(pods_result.stdout)
        images_to_scan = []

        for pod in pods_data.get('items', []):
            for container in pod.get('spec', {}).get('containers', []):
                images_to_scan.append(container.get('image'))

    except json.JSONDecodeError:
        return render_template('results.html', results={"error": "Failed to parse pod data."})

    # Get the name of the Trivy pod
    trivy_pod_cmd = f"kubectl get pods -n {NAMESPACE} -l app=trivy -o jsonpath='{{.items[0].metadata.name}}'"
    trivy_pod_result = subprocess.run(trivy_pod_cmd, shell=True, capture_output=True, text=True)

    if trivy_pod_result.returncode != 0:
        return render_template('results.html', results={"error": trivy_pod_result.stderr})

    trivy_pod_name = trivy_pod_result.stdout.strip()

    # Scan each image for vulnerabilities
    for image in set(images_to_scan):  # Use set to avoid duplicate scans
        try:
            # Command to execute Trivy scan on each image
            cmd = f"kubectl exec -n {NAMESPACE} {trivy_pod_name} -- trivy image --format json {image}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                results[image] = json.loads(result.stdout)  # Parse JSON result
            else:
                results[image] = {"error": result.stderr}

        except Exception as e:
            results[image] = {"error": str(e)}

    return render_template('results.html', results=results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
