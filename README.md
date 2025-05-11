# SomeBot
---

### **Complete Project: SomeBot with Humor, Trivy & OWASP Analysis, Ollama and Deployment**

---

Precondtion: Docker for Desktop and running k8s-Cluster (local) 

#### **1. ArgoCD deloyment and Connection**

```bash
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl apply -n argocd -f argocd-app.yaml
kubectl port-forward svc/argocd-server -n argocd 8088:443
kubectl get secret argocd-initial-admin-secret -n argocd -o jsonpath='{.data.password}' | base64 -d
```

---
#### **2. Checkout repro and modify **
```bash
1. clone repo 
2. modify things for your repro
3. See a running pipeline
```

#### **3. Let's run **
```bash
1. go on somebot via shell
2. run command: python bazinga_cve_bot.py
3. See your message in discord channel
```