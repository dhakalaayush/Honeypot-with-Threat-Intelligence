# Honeypot with Automated Threat Intelligence

This system captures malicious login attempts and unauthorized HTTP requests via ports 22 and 80. It queries threat intelligence APIs to score the IP address, logs and ingest into the database. The data is visualized on a real-time dashboard.

## Architecture

![Block Diagram](Design/Block_diagram.svg)

## Deployment

Install requirements

    pip install -r requirements.txt

Initialize database

    python database.py

Run the server

    python server.py

Launch Grafana

    docker compose up -d

Create Total Attacks visualization in Grafana

    SELECT timestamp AS time, 
    count(*) AS total_attacks 
    FROM attacks 
    GROUP BY timestamp;

Create Top Targeted Services visualization in Grafana

    SELECT attack_type, 
    count(*) AS hits 
    FROM attacks 
    GROUP BY attack_type;

Create Malicious IPs table in Grafana

    SELECT ip, country, abuse_score, 
    count(*) AS attempts 
    FROM attacks 
    WHERE abuse_score > 0 
    GROUP BY ip 
    ORDER BY abuse_score DESC 
    LIMIT 10;
