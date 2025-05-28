
# 🐷 Snort Cheatsheet

A compact reference guide for working with **Snort**, the powerful open-source network intrusion detection system (NIDS). This cheat sheet covers common commands, rule structures, and configurations.

- [📄 Snort Cheatsheet pdf](./Snort Cheatsheet.pdf)
  
---

## 📌 Snort Basic Modes

| Mode            | Command Example                                  |
|-----------------|--------------------------------------------------|
| **Version Info**| `snort -V` or `snort --version`                  |
| **Quiet Mode**  | `snort -q`                                       |
| **Interface**   | `snort -i eth0`                                  |
| **Verbose**     | `snort -v`                                       |
| **Headers**     | `snort -e` (link-layer) / `snort -d` (data)      |
| **Hex Dump**    | `snort -X`                                       |
| **All Details** | `snort -eX`                                      |
| **Packet Count**| `snort -v -n 10`                                 |
| **Run Config**  | `snort -c /etc/snort/snort.conf`                 |
| **Test Config** | `snort -c /etc/snort/snort.conf -T`              |
| **No Logging**  | `snort -c /etc/snort/snort.conf -N`              |
| **Background**  | `snort -c /etc/snort/snort.conf -D`              |

---

## ⚠️ Alert Modes

| Mode                     | Command Example |
|--------------------------|-----------------|
| No Output                | `snort -A none` |
| Console Output (type 1)  | `snort -A console` |
| Console Output (type 2)  | `snort -A cmg` |
| File Output (fast)       | `snort -A fast` |
| File Output (full)       | `snort -A full` |

---

## 🧪 Using Rules Directly

```bash
snort -c /etc/snort/rules/local.rules -v -A console
```

---

## 📂 Logging

| Feature                 | Command Example |
|-------------------------|-----------------|
| **Default Path**        | `/var/log/snort` |
| **Custom Path**         | `snort -l /custom/path` |
| **ASCII Logging**       | `snort -K ASCII` |
| **Read Log**            | `snort -r snort.log` |
| **Read N Packets**      | `snort -r snort.log -n 10` |
| **BPF Filtering**       | `snort -r snort.log 'udp and port 53'` |

---

## 🗂 PCAP Processing

| Task                        | Command |
|-----------------------------|---------|
| Single File                 | `snort -c snort.conf -r file.pcap -A console` |
| Multiple Files              | `snort -c snort.conf --pcap-list="file1.pcap file2.pcap" -A console` |
| From Folder                 | `snort -c snort.conf --pcap-dir=/path/to/folder -A console` |
| Show PCAP Name              | `--pcap-show` flag |

---

## 🧠 Snort Rule Structure

### 🔹 Rule Format

```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

### 🔸 Example Rule

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"Directory Traversal Attempt!";
    flow:established;
    nocase;
    content:"HTTP";
    fast_pattern;
    content:"|2E 2E 2F|";
    content:"/..";
    session:all;
    reference:CVE,XXX;
    sid:100001;
    rev:1;
)
```

---

## 🧩 Rule Components

| Component       | Description |
|-----------------|-------------|
| `alert`         | Action to take (alert, log, pass, etc.) |
| `tcp`           | Protocol (TCP, UDP, ICMP, IP) |
| `$EXTERNAL_NET` | Source IP placeholder |
| `$HOME_NET`     | Destination IP placeholder |
| `$HTTP_PORTS`   | Destination ports placeholder |
| `msg`           | Message on match |
| `sid`           | Unique rule ID |
| `rev`           | Revision of the rule |
| `flow`          | Flow direction (e.g. established) |
| `nocase`        | Case-insensitive match |
| `content`       | Content to match |
| `fast_pattern`  | Speeds up matching |
| `session`       | Session tracking |
| `reference`     | CVE or link reference |

---

## 📚 Resources

- TryHackMe Room: [Snort](https://tryhackme.com/room/snort)

---

## 📎 License

This cheat sheet is provided for educational purposes. Feel free to fork and contribute!
