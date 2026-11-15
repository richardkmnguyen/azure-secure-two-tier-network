Watch me explain this lab: [LoomLink](https://www.loom.com/share/baa80df7701747efaceebdf1d4528f47)

# azure-secure-two-tier-network

Built a classic two tier network on Azure: a web server in a public subnet, a database server in a private subnet with no public IP, and NSG rules that let **only the web subnet** reach the database. A third test VM proved the lockdown works: before the rules, it could ping the database. After them, the same ping got 100% packet loss, while the web server still connected normally. Network Watcher's IP flow verify confirmed the same port on the same VM is allowed from one subnet and denied from another.

# Azure Cloud Series, Lab 02: Secure 2-Tier Web Application

**Azure Virtual Network · Subnets · Network Security Groups · Linux VMs (Ubuntu) · OpenSSH ProxyJump · Network Watcher · Azure Portal**

[Lab 01](https://github.com/richardkmnguyen/azure-static-website-blob-storage) hosted a website with no server at all. This lab goes the other way: real servers, real network design, and the question every multi-tier app has to answer. How do you let the internet reach your web server without letting it anywhere near your database? This is the second lab of a six week Azure series that ends in a capstone project.

| | |
|---|---|
| **Platform** | Azure Portal and PowerShell (built-in OpenSSH client) on a local Windows PC, against East US on my personal Azure subscription |
| **Time** | About 1.5 hours |

---

## What this lab is for

The business problem: a company runs a customer facing web app backed by a database full of customer data. The web server has to be reachable from the internet. The database must not be. And if any other machine on the network is ever compromised, it shouldn't be able to reach the database either.

Four ideas make that work:

- **Segmentation.** The web tier and the data tier live in separate subnets, so traffic between them can be filtered.
- **No public IP on the database.** If a VM has no public IP, nothing on the internet can start a connection to it. That's the first wall.
- **NSG rules are evaluated by priority, lowest number first.** The first rule that matches wins, so an Allow at 100 and a Deny at 200 means "this source only, nobody else."
- **A jump host for admin access.** The database is managed by SSHing through the web server, not by exposing it.

| VM | Subnet | Public IP | Role |
|---|---|---|---|
| `vm-web-01` | `snet-web` 10.0.1.0/24 | Yes (ports 22, 80) | Front end, and the SSH jump host |
| `vm-db-01` | `snet-db` 10.0.2.0/24 | **None** | Back end, the server being protected |
| `vm-test-01` | `snet-test` 10.0.3.0/24 | None | Validation host: a VNet machine that should be blocked |

---

## Architecture

```
My local Windows PC (PowerShell + OpenSSH)
        │
        │  SSH 22 / HTTP 80
        ▼
Azure subscription (personal)
        │
        └── rg-lab02-richard (East US)
                │
                └── vnet-lab02  10.0.0.0/16
                        │
                        ├── snet-web   10.0.1.0/24
                        │       └── vm-web-01   public IP, NSG allows 22 + 80
                        │               │
                        │               │  allowed (Allow-Web-Subnet, priority 100)
                        │               ▼
                        ├── snet-db    10.0.2.0/24
                        │       └── vm-db-01    10.0.2.4, NO public IP
                        │               ▲
                        │               │  denied (Deny-VNet-Inbound, priority 200)
                        │               │
                        └── snet-test  10.0.3.0/24
                                └── vm-test-01  10.0.3.4, no public IP
```

<!-- SCREENSHOT: TwoTierArchitecture — architecture diagram from the SOP -->

| Component | Role |
|---|---|
| **`rg-lab02-richard`** | Resource group holding everything, so cleanup is one delete |
| **`vnet-lab02`** | Virtual network, `10.0.0.0/16`, split into three `/24` subnets |
| **`vm-web-01`** | Ubuntu Server 24.04 LTS, Standard_D2als_v7, public IP, the only VM reachable from the internet |
| **`vm-db-01`** | Same image and size, private IP only, protected by its NSG |
| **`vm-test-01`** | Same image and size, private IP only, exists to prove the Deny rule works |
| **`vm-db-01-nsg`** | Network security group on the DB's network interface: Allow web subnet (100), Deny all other VNet traffic (200) |
| **`key-lab02`** | SSH key pair generated in Azure, shared by all three VMs |

---

## What I built

### 1. Built the network
Created `vnet-lab02` with address space `10.0.0.0/16` and three subnets: `snet-web` (10.0.1.0/24), `snet-db` (10.0.2.0/24), and `snet-test` (10.0.3.0/24). The test subnet wasn't in the original guide I looked at. I added it so there would be a machine inside the VNet but outside the web tier to test the lockdown against.

<img width="1552" height="784" alt="image" src="https://github.com/user-attachments/assets/7bc6a141-5ab3-4ac3-b25f-b9044051ae5b" />

### 2. Deployed the three VMs
All three run Ubuntu Server 24.04 LTS on **Standard_D2als_v7**. I originally planned to use Standard_B1s, but it wasn't available to me: the original B-series is scheduled for retirement in 2028, and Azure has restricted new deployments of it since July 2026.

- **`vm-web-01`:** public IP, inbound SSH (22) and HTTP (80), new key pair `key-lab02`.
- **`vm-db-01`:** subnet `snet-db`, public IP **None**, public inbound ports **None**, existing key `key-lab02`.
- **`vm-test-01`:** subnet `snet-test`, public IP None, public inbound ports None.

<img width="1288" height="271" alt="2TierAppVMDB01NoPublicIP" src="https://github.com/user-attachments/assets/482aee4e-967f-43d6-ae76-60c6d9cc26cd" />

> No public IP for vm-db-01

### 3. Set up SSH from Windows without PuTTY
Windows 10/11 ships with OpenSSH, so everything ran from PowerShell. OpenSSH refuses a private key other accounts can read, so I locked it down first:

```powershell
icacls "$env:USERPROFILE\.ssh\key-lab02.pem" /inheritance:r /grant:r "$($env:USERNAME):(R)"
```
<img width="581" height="117" alt="2TierAppKeyPermissions" src="https://github.com/user-attachments/assets/f0cd1a38-3a4c-49bb-8d97-23362d9cd096" />

Then I wrote an SSH config file so the database and test VM are reached *through* the web server with ProxyJump. The private key never gets copied onto the jump host, which is what the original guide I planned to follow would have required:

```
Host lab02-web
    HostName <public-ip-of-vm-web-01>
    User azureuser
    IdentityFile ~/.ssh/key-lab02.pem

Host lab02-db
    HostName 10.0.2.4
    User azureuser
    IdentityFile ~/.ssh/key-lab02.pem
    ProxyJump lab02-web

Host lab02-test
    HostName 10.0.3.4
    User azureuser
    IdentityFile ~/.ssh/key-lab02.pem
    ProxyJump lab02-web
```

After that, `ssh lab02-db` from my PC lands on a server with no public IP in one command. The file is saved in this repo as [`ssh/config.example`](ssh/config.example).

<img width="453" height="461" alt="2TierAppDB01LoginSucess" src="https://github.com/user-attachments/assets/9eaa5368-64c9-404c-b950-2ae5743c7d65" />

> Successful SSH into vm-db-01

### 4. Captured the "before" state
Before touching any rules, I tested from both the web VM and the test VM:

```bash
# from vm-web-01
ping -c 4 10.0.2.4     # replies
# from vm-test-01
ping -c 4 10.0.2.4     # replies
```

Both worked. That's the gap this lab closes. Azure's default `AllowVnetInBound` rule (priority 65000) lets every machine in the VNet reach every other machine, so "no public IP" alone doesn't stop a compromised VM inside the network from reaching the database.

<img width="407" height="579" alt="2TierAppWeb01SSHAndPingSucceed" src="https://github.com/user-attachments/assets/f8fcee82-7792-475f-8ad0-7c8b7fe773ef" />
<img width="451" height="580" alt="2TierAppTest01SSHAndPingSucceed" src="https://github.com/user-attachments/assets/86c4303d-eec4-44e1-8398-cace38a608e2" />

> Successful SSH and Pings for vm-web-01 and vm-test-01

### 5. Locked down the database with two NSG rules
On `vm-db-01-nsg`, I added:

| Priority | Name | Source | Destination ports | Protocol | Action |
|---|---|---|---|---|---|
| 100 | `Allow-Web-Subnet` | `10.0.1.0/24` | `*` | Any | Allow |
| 200 | `Deny-VNet-Inbound` | Service tag `VirtualNetwork` | `*` | Any | Deny |

The original guide only added the Allow rule, and said it ensures only the web subnet can talk to the DB. It doesn't: `AllowVnetInBound` already allows the whole VNet, so an extra Allow changes nothing. The Deny at 200 is what actually blocks everything else, and it sits well ahead of the default rule at 65000.

<img width="1913" height="762" alt="2TierAppNSGRules" src="https://github.com/user-attachments/assets/2b28aa23-6409-43e8-8c70-a7a2e4146d9a" />

### 6. Validated: after
Same tests, plus TCP checks, after the rules saved:

| From | Command | Result | What it proves |
|---|---|---|---|
| `vm-web-01` | `ping -c 4 10.0.2.4` | Replies | Web tier still reaches the DB |
| `vm-web-01` | `nc -zv 10.0.2.4 22` | Succeeded | TCP allowed from the web subnet |
| My PC | `ssh lab02-db` | Logged in | Jump-host access still works |
| `vm-test-01` | `ping -c 4 10.0.2.4` | **100% packet loss** | Deny rule blocks other subnets |
| `vm-test-01` | `nc -zv -w 5 10.0.2.4 22` | **Timed out** | The Deny covers TCP, not just ping |
| `vm-db-01` | `ping -c 4 10.0.3.4` | Replies | NSG rules here are inbound only, and NSGs are stateful |

<img width="319" height="151" alt="2TierAppWeb01SuccessPostNSGRules" src="https://github.com/user-attachments/assets/ad650d9f-f802-4460-b570-b66eba266d91" />
<img width="377" height="108" alt="2TierAppTest01FailPostNSGRules" src="https://github.com/user-attachments/assets/9a8598dc-90f8-4722-b06f-374999f3dcc7" />

> Same database, same port, two different answers depending on which subnet is asking. That's segmentation working.

<img width="592" height="361" alt="2TierAppDB01LoginSucessPostNSGRules" src="https://github.com/user-attachments/assets/9c8c9c9a-c571-4d88-a4d1-08b32d86fabb" />
<img width="316" height="128" alt="2TierAppDB01InternalPingSuccessPostNSGRules" src="https://github.com/user-attachments/assets/7490f8d4-8ebb-4482-ad8e-125ca7e2b7fe" />

> Login and ping from vm-db-01 both pass

### 7. Confirmed it from Azure's side with IP flow verify
Commands inside the VMs show *that* traffic is blocked. Network Watcher's **IP flow verify** shows *which rule* blocked it. With `vm-db-01`'s network interface selected, TCP, Inbound, local `10.0.2.4:22`:

- Remote `10.0.3.4` (test VM): **Access denied**, by `Deny-VNet-Inbound`
- Remote `10.0.1.4` (web VM): **Access allowed**, by `Allow-Web-Subnet`

<img width="581" height="836" alt="2TierAppNetworkWatcherIPflowFail" src="https://github.com/user-attachments/assets/6dd879be-c8b8-4e2e-a2eb-3a363ac91791" />
<img width="583" height="845" alt="2TierAppNetworkWatcherIPflowSucceed" src="https://github.com/user-attachments/assets/36f110e9-05ab-46b3-a8a9-6ae79b9d038a" />

---

## Changes from the original guide I planned to follow

| Original guide | What I did instead | Why |
|---|---|---|
| Only an Allow rule for the web subnet | Allow at 100 **plus** Deny `VirtualNetwork` at 200 | The default `AllowVnetInBound` already allows the whole VNet; without a Deny, nothing was restricted |
| No way to test the restriction | Added `snet-test` and `vm-test-01` | A lockdown you can't show failing isn't proven |
| DB VM opened SSH (22) to the internet in its NSG | Public inbound ports: None | No public IP made it moot, but the rule shouldn't exist |
| Copy the `.pem` key onto the web server to reach the DB | OpenSSH `ProxyJump` from my PC | The private key never leaves my machine |
| Ubuntu Server 20.04 LTS | Ubuntu Server 24.04 LTS | 20.04 is past end of standard support |
| Standard_B1s | Standard_D2als_v7 | Original B-series is restricted for new deployments ahead of its 2028 retirement |

---

## Key takeaways

1. **No public IP isn't the same as isolated.** It stops the internet, but by default every VM in the VNet can still reach every other VM. The real lockdown is the NSG.
2. **An Allow rule on its own can do nothing.** Azure's defaults already allow VNet traffic, so restricting access takes a Deny, and priority decides which rule wins.
3. **Prove a block with something that should be blocked.** Testing only from the web server would have looked identical with or without the Deny rule. The test VM is what made the result mean something.
4. **Two kinds of evidence are better than one.** Ping and `nc` showed the traffic failing; IP flow verify showed the exact rule responsible.
5. **Jump hosts don't need your key.** ProxyJump gets you to a private server without leaving credentials on the box in between.

If I did this again, I would apply the NSG at the **subnet** level instead of the DB's network interface, so any future database VM in `snet-db` is protected automatically, and I would deploy the whole thing with Terraform after the portal run.

---

## Security notes

This is a lab configuration. Some of it is solid and some of it would not be acceptable in production:

**What the lab does well**
- **The database has no public IP** and accepts traffic only from the web subnet, enforced by an explicit Deny.
- **SSH key authentication only**, no passwords, and the private key stays on my PC.
- **Separate subnets per tier**, so rules can be written per tier instead of per machine.
- **Personal subscription, one resource group**, deleted after the lab.

**What I would change for production**
- **Replace the jump host with Azure Bastion**, and close SSH on the web VM's public IP entirely (or at least restrict it to my IP).
- **Narrow the Allow rule to the database port** (3306 for MySQL, 5432 for PostgreSQL) instead of all ports.
- **Use Application Security Groups**, so rules reference "web servers" and "database servers" instead of IP ranges.
- **Put the web tier behind Application Gateway with a WAF** instead of a public IP on the VM itself.
- **Turn on NSG flow logs** to Log Analytics so denied traffic is recorded, not just blocked.
- **Use a managed database (Azure Database for MySQL/PostgreSQL) with Private Endpoint** instead of a database on a VM.

---

## Verification

| Check | How I verified it |
|---|---|
| Network built | `vnet-lab02` with `snet-web`, `snet-db`, `snet-test` at the planned ranges |
| DB is private | `vm-db-01` Overview: private IP 10.0.2.4, no public IP |
| Jump access works | `ssh lab02-db` from my PC lands on `vm-db-01` |
| Gap existed before | Test VM could ping the DB before the NSG rules |
| Rules in place | `vm-db-01-nsg`: Allow-Web-Subnet (100), Deny-VNet-Inbound (200) |
| Web tier allowed | Ping and `nc` to port 22 from `vm-web-01` succeeded |
| Other subnets blocked | Ping 100% loss and `nc` timeout from `vm-test-01` |
| Azure agrees | IP flow verify: denied from 10.0.3.4, allowed from 10.0.1.4, each naming the matching rule |

---

## Teardown

Deleting the resource group removes all three VMs, their disks, network interfaces, NSGs, the public IP, and the VNet in one step.

```
Resource groups → rg-lab02-richard → Delete resource group → type the name → Delete
```

Or with the Azure CLI:

```powershell
az group delete --name rg-lab02-richard --yes
az group show --name rg-lab02-richard   # expect ResourceGroupNotFound
```

Then remove the `lab02-*` entries from `~/.ssh/config` and the matching lines from `~/.ssh/known_hosts`.

---

## Next steps

- Rebuild the whole lab with **Terraform**: VNet, subnets, VMs, and NSG rules in code
- Swap the jump host for **Azure Bastion**
- Install **MySQL** on `vm-db-01` and narrow the Allow rule to port 3306
- Move the rules to a **subnet-level NSG** with **Application Security Groups**
- Carry the network pattern into the series capstone

---

**Status: complete.** Built a VNet with web, database, and test subnets → deployed three Ubuntu VMs, with only the web VM public → SSH'd through the web VM to the private servers with ProxyJump → showed the test VM could reach the DB by default → added Allow (100) and Deny (200) NSG rules → test VM blocked, web VM allowed → IP flow verify confirmed both by rule name.
