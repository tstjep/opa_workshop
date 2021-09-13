# OPA Gatekeeper Tutorial!

Hi! Welcome to this introduction tutorial to OPA and OPA Gatekeeper.
Like in school I'll give you tasks which you need to solve, nevertheless I hope this won't just be a chore :)

I suggest you to use the [Rego Playground](https://play.openpolicyagent.org/) to write and test your rego code, alternatively feel free to play with your favorite IDE.

The solutions are located at the end of this page.

# Useful Links
Rego Docs:

https://www.openpolicyagent.org/docs/latest/policy-language/#what-is-rego

Excellent Rego Summary Slideshare:
https://www.slideshare.net/TorinSandall/rego-deep-dive

Intro to Kubernetes Admission Control:
https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/

# Task 1 - Pure Rego Intro
Input JSON:

    {"firstname": "mani", "lastname": "matter"}

 1. Create a Rego Policy which checks for firstname "mani":

Useful Rego concepts: 

 - (Default) Variables
 - "input" Keyword
 - JSON traversing
 - Rule with string comparison

2. Now extend your rego code to also check if the lastname starts with the letter "m" (AND)
3. When that works change the rule check for firstname "mani" OR lastname "matter".

Useful Rego concepts: 

 - AND vs OR in rules

# Task 2 - Rego for K8s
Use following JSON, with real Kubernetes AdmissonReview object, trying to start a Pod with two Containers:

    {
      "apiVersion": "admission.k8s.io/v1beta1",
      "kind": "AdmissionReview",
      "review": {
        "kind": {
          "group": null,
          "kind": "Pod",
          "version": "v1"
        },
        "object": {
          "metadata": {
            "name": "myapp"
          },
          "spec": {
            "containers": [
              {
                "image": "nginx:latest",
                "name": "nginx-frontend"
              },
              {
                "image": "mysql",
                "name": "mysql-backend"
              }
            ]
          }
        }
      }
    }
Please
 - Only allow images from the "swisscom.com" Repository.
 - Also deny images with the latest tag
 
You can ignore possible InitContainers for now.

Boilerplate code:

    package kubernetes.admission
    violation[{"msg": msg, "details": {}}] {
             #loop through container images
             ....
             msg := sprintf("error message: %v", [image])
     }

Rego Concepts:

 - https://www.openpolicyagent.org/docs/latest/#iteration
 - Negation
 - Startswith() function

Bonus question:
How would you include InitContainers into the same check?

# Task 3 - Create Kubernetes CRDs and install them in your cluster
 1. Install https://github.com/open-policy-agent/gatekeeper to your minikube cluster:
 `kubectl apply -f deploy/gatekeeper.yaml`


 2. Now create both the Policy template and the corresponding Policy constraint using the rego code from Task 2. 
Please consult the [documentation](https://github.com/open-policy-agent/frameworks/tree/master/constraint#opa-constraint-framework) regarding Constraints and ConstraintTemplates. 
You might also find inspiration in the official policy library with many examples:
https://github.com/open-policy-agent/gatekeeper-library/tree/master/library/general
2. Apply both yamls (creates the K8s CRDs for OPA Gatekeeper):
`kubectl apply -f template_Task2.yaml`
`kubectl apply -f constraint_Task2.yaml`
3. Try to deploy something, e.g.:
`kubectl create deployment nginx --image=nginx`
4. What happens? Should the Pod get started? Inspect its ReplicaSet
5. Change your policy to only warn and not reject (no change of the Rego code necessary)
6. How would you exclude a certain namespace from that policy?
7. How would you exclude a namespace from Gatekeeper globally?


# Bonus Task 4 - Replace any PSP functionality with a Rego Policy (e.g. no privileged pods)


# Solution

## Task 1

    package checkswissmusician
     
    firstname := input.firstname
    lastname := input.lastname
     
    default allow = false
     
    allow {
      firstname == "mani"
      #lastname == "matter"
    }
    
    allow {
      lastname == "matter"
    }

## Task 2

    package kubernetes.admission
     deny[msg] {
         input.request.kind.kind == "Pod"
         image := input.request.object.spec.containers[_].image
         not startswith(image, "swisscom.com")
         msg := sprintf("image not from trusted registry: %v", [image])
    }
     deny[msg] {
         input.request.kind.kind == "Pod"
         image := input.request.object.spec.containers[_].image
         endswith(image, ":latest")
         msg := sprintf("image has latest tag: %v", [image])
    }

## Task 3
https://github.com/tstjep/opa_workshop/blob/main/task2_constraint.yaml
https://github.com/tstjep/opa_workshop/blob/main/task2_template.yaml

## Bonus Task
https://github.com/open-policy-agent/gatekeeper-library/tree/master/library/pod-security-policy
