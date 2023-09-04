'''
Upgrade Script to enable Vsphere K8s Cluster APi Server -  Encrypting Confidential Data at Rest - Feature
'''
import subprocess
import paramiko
import os
import base64
import yaml
import paramiko
import time
import sys

def scp_copy(source_path, destination_path, hostname, username="atom", password="secret@123"):
    transport = paramiko.Transport((hostname, 22))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put(source_path, destination_path)
    sftp.close()
    transport.close()    


def generate_random_base64(length=32):

    random_bytes = os.urandom(length)
    base64_encoded = base64.b64encode(random_bytes).decode('utf-8')
    return base64_encoded

def getSSHClient(host, username, password, ssh_retry=5, ssh_timeout=300):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for retry in range(ssh_retry):
            try:
                client.connect(host, username=username, password=password, timeout=ssh_timeout)
                return client
            except Exception as e:
                #logging.error(str(e))
                time.sleep(30)
        #logging.error("Failed to establish ssh connection, exiting..")
        sys.exit(1)


def execute(command, current_exec_same_node=True, host="", username="", password="" ):
   #utility inside body
   def executeRemoteCommand(command, host, username, password):
      ssh_client = getSSHClient(host, username, password )
      stdin, stdout, stderr= ssh_client.exec_command(command)
      ssh_client.close()
      return  stdout.readlines(), stderr.readlines()
      
   def executeCommand(command):
        wait = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,encoding="utf-8")
        output, error = wait.communicate()
        return output, error
   
   
       
   #execute body 
   if current_exec_same_node:
      return executeCommand(command)
   else:
      return executeRemoteCommand(command, host, username, password)
    

def enable_encryption_config_on_apiserver(username, password):
    
    def backup_apiserver(current_exec_same_node=True, node="", username="", password=""):
        command = "sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/manifests/kube-apiserver.yaml.bkp"
        execute(command, current_exec_same_node, node, username, password)
        
        command = "sudo ls /etc/kubernetes/manifests/kube-apiserver.yaml.bkp | grep kube-apiserver.yaml.bkp"
        output, error = execute(command, current_exec_same_node, node, username, password)        
        if "kube-apiserver.yaml.bkp" in str(output):
           return True 
        return False   
                            
    def generate_config_file(): 

        command = """ if [ -e /etc/kubernetes/enc/encryption.yaml ]; then echo "Config Present..." ; else 
        sudo mkdir -p /etc/kubernetes/enc; 
        sudo echo Creating Config file...; 
        fi"""
        output, error = execute(command)
        print(output, error)

        config_dict = {   'apiVersion': 'apiserver.config.k8s.io/v1',
                          'kind': 'EncryptionConfiguration',
                          'resources': [
                            { 'resources': ['secrets'],
                              'providers': [
                                   {'aesgcm': {'keys': [
                                                         {'name': 'key1', 'secret': 'AESGCM1_32'},
                                                         {'name': 'key2', 'secret': 'AESGCM2_32'}
                                                       ]
                                              }
                                   },
                                   {'aescbc': {'keys': [
                                                       {'name': 'key1', 'secret': 'AESCBC1_32'},
                                                       {'name': 'key2', 'secret': 'AESCBC2_32'}
                                                     ]
                                            }
                                   },
                                   {'secretbox': {'keys': [
                                                          {'name': 'key1', 'secret': 'BOX_32'}
                                                        ]
                                               }
                                   },
                                   {'identity': {}}
                              ]
                            }
                          ]
                        }

        config_dict["resources"][0]["providers"][0]["aesgcm"]["keys"][0]["secret"] = generate_random_base64(32)
        config_dict["resources"][0]["providers"][0]["aesgcm"]["keys"][1]["secret"] = generate_random_base64(32)
        config_dict["resources"][0]["providers"][1]["aescbc"]["keys"][0]["secret"] = generate_random_base64(32)
        config_dict["resources"][0]["providers"][1]["aescbc"]["keys"][1]["secret"] = generate_random_base64(32)
        config_dict["resources"][0]["providers"][2]["secretbox"]["keys"][0]["secret"] = generate_random_base64(32)

        if "Creating" in str(output):
            with open("/etc/kubernetes/enc/encryption.yaml", "w") as file:
               yaml.dump(config_dict, file)
        
        #print("configuring api server yaml")   
        command = """#Mount enc folder as volume inside container
export VAR=`cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -i 'encryption-provider-config'`
if [ -n '$VAR' ]; then echo "---------------------------------------------------------------> Zero Changes"; else  
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.volumes[+].name' enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.volumes.(name==enc).hostPath.path' /etc/kubernetes/enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.volumes.(name==enc).hostPath.type' DirectoryOrCreate
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.containers[0].volumeMounts[+].name' enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.containers[0].volumeMounts.(name==enc).mountPath' /etc/kubernetes/enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.containers[0].volumeMounts.(name==enc).readOnly' true
sudo yq w -i -- /etc/kubernetes/manifests/kube-apiserver.yaml spec.containers[0].command[+] --encryption-provider-config=/etc/kubernetes/enc/encryption.yaml;
fi
"""
        output, error = execute(command)
        return output, error
       
       	
    def confiugure_apiserver_on_master(node, username, password): 
         ssh_client = getSSHClient(node, username, password )   
         command="""sudo mkdir -p /etc/kubernetes/enc
sudo echo `/etc/kubernetes`                    
sudo mv /tmp/encryption.yaml /etc/kubernetes/enc/encryption.yaml
sudo ls /etc/kubernetes/enc/
#Mount enc folder as volume inside container
VAR=`cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -i 'encryption-provider-config'`

if [ -n '$VAR' ]; then echo "--------------------------------------------------------> Zero Changes"; else  
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.volumes[+].name' enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.volumes.(name==enc).hostPath.path' /etc/kubernetes/enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.volumes.(name==enc).hostPath.type' DirectoryOrCreate
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.containers[0].volumeMounts[+].name' enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.containers[0].volumeMounts.(name==enc).mountPath' /etc/kubernetes/enc
sudo yq w -i /etc/kubernetes/manifests/kube-apiserver.yaml 'spec.containers[0].volumeMounts.(name==enc).readOnly' true
sudo yq w -i -- /etc/kubernetes/manifests/kube-apiserver.yaml spec.containers.[0].command[+] --encryption-provider-config=/etc/kubernetes/enc/encryption.yaml;
fi"""
         
         stdin,stdout,stderr= ssh_client.exec_command(command)
         output = stdout.readlines()
         print(output)
         return output, stderr.readlines()
        
    def current_node_ip():
        command='''ssh ${ip} "kubectl get pods -n kube-system -o=jsonpath='{range .items[*]}{.spec}{"\n"}{end}' | grep encryption-provider-config"'''.format(ip=ip)
        output, error = execute(command)
        if "encryption-provider-config" in output:
           return True
        return False 
    
    def pod_is_running(pod, ns="kube-system", current_exec_same_node=True, node="", username="", password=""):          
        command = f"kubectl get pod/{pod} -n {ns} """ + """-o=jsonpath='{.status.phase}'"""  
        if current_exec_same_node:
           output, error = execute(command)
        else:
           output, error = execute(command, False, node, username, password ) 
        return output, error  
        
        if "Running" in str(output):
            return True
        return False   
        
    def delete_pod( pod, node="", current_exec_same_node=True, username="", password=""):      
        command = f"kubectl delete pod/{pod} -n kube-system"
        if current_exec_same_node:
           output, error = execute(command)
        else:
           output, error =execute(command, False, node, username, password ) 
        return output, error    
            
    def is_api_server_configured():
        """ Check if any API Server is configured, ideally all API Servers would be configured. 
        This configuration is optional, if not not all API Servers are configured system would crash"""
        
        command="""Pods=`kubectl get pods -n kube-system -o=jsonpath='{range .items[*]}{.spec}{"\n"}{end}' | grep 'encryption-provider-config' | wc -l`
                   Nodes=`kubectl get node |grep master |  wc -l`
                   if [ ${Pods} = ${Nodes} ]; then echo "All Pods Configured"; else echo "" ;fi"""
        output, error = execute(command)
        # log output check_api_server_configured
        #print("check_api_server_configured output: ", output)

        if "All Pods Configured" in str(output):
           print("API Server's Configured with Encryption Config !")
           return True
        print("Not All/ None of API Servers configured with Encryption Config !")
        return False 

    def restart_api_server(pod_name="", current_exec_same_node=True, host="", username="", password="", ns="kube-system" ):
        print(pod_name, "kube-system", False, host, username, password)
        for i in range(5):
            time.sleep(10)
            status = pod_is_running(pod_name, "kube-system", current_exec_same_node, host, username, password)
            if status:
              return True
        return False
    ##################   main code for enable_encryption_config_on_apiserver ##################
    
    import socket
   
    current_node_name = socket.gethostname()
    
    current_master_ip=""
    
    command = """kubectl get nodes -o=jsonpath='{range .items[*]}{.metadata.name}/{.status.addresses[?(@.type=="InternalIP")].address}{"\t"}{end}'"""
    
    output, error = execute(command)

    nodes = {}   
    for node in output.split("\t"):  
       if len(node) and "/" in node and "master" in node:  
          name, ip = node.split("/")  
          nodes[name]=ip
          if current_node_name ==  name:
             current_master_ip = ip
            
              
    command = """kubectl -n kube-system get pods -l component=kube-apiserver -o=jsonpath='{range .items[*]}{.metadata.name}/{.spec.nodeName}{"\t"}{end}'"""
    output, error = execute(command)
    
    apiserver_node_pod_map = {}   
    for node in output.split("\t"):  
        if len(node) and "/" in node and "master" in node and "apiserver" in node:  
           pod, node = node.split("/")  
           apiserver_node_pod_map[node]=pod
           
    print(apiserver_node_pod_map)
    print( nodes)
    #print(nodes, current_master_ip)               
    all_masters_contains_config_file=True   
   
    check_config="""if [ -e '/etc/kubernetes/enc/encryption.yaml' ]; then   echo "present"; else   echo "none"; fi""" 
    print(f"      Encryption config file on Node                     Status              ")
    for name in nodes:  
       ip = nodes[name]   
       if ip == current_master_ip:
          output, error = execute(check_config)
       else:
          output, error = execute(check_config, False, ip, username, password )
       
       config = str(output)  
       
       if "none" in config:  
           all_masters_contains_config_file = False
           print(f"        {name}                     not present")   
       else:
           print(f"        {name}                     present")   
               
    print(f"\n Encryption config file present:", all_masters_contains_config_file)
   
    # True if all pods configured
    server_configured = is_api_server_configured()
         
    if all_masters_contains_config_file :
           if server_configured:
               print("Configuration present on pods")
               sys.exit(0)
            
    if not server_configured:
        
        print(f"\nGenerating Configuration on Control Node {current_node_name}, please wait...\n")
        
        backup_apiserver()
        
        generate_config_file()
  
        delete_pod(apiserver_node_pod_map[current_node_name],"", True, username, password)
        
        time.sleep(10)
        
        if pod_is_running( apiserver_node_pod_map[current_node_name] ): 
            print( f"pod {apiserver_node_pod_map[current_node_name]} on {current_node_name} is Up...\n\n")
            for name in nodes: 
               
               ip = nodes[name]
               
               if ip in current_master_ip:
                  continue     
                  
               print(f"Copy file to {name}{ip}..." )   
               
               scp_copy("/etc/kubernetes/enc/encryption.yaml", "/tmp/encryption.yaml", ip, username, password)
               print(f"Back up..." )   
               backup_apiserver( False, ip, username, password)
               print(f"Configure..." )   
               confiugure_apiserver_on_master( ip, username, password)               
               print(f"Pod Status: ..." )   
               api_server_isup = restart_api_server( apiserver_node_pod_map[name], False, ip, username, password, "kube-system")
               status = "Up"   
               if not api_server_isup :
                  status = "Down"
               print( f"Api Server {apiserver_node_pod_map[name]} on this node is {name} is {status}!" )
        # of all pods are up    
        if is_api_server_configured():
            #update_secrets
            execute("kubectl get secrets --all-namespaces -o json | kubectl replace -f -")            
    else:
       print("API Servers configured with Encryption configuration!")  
       
       
                
if __name__ == "__main__":           
  enable_encryption_config_on_apiserver("test", "012345")    
