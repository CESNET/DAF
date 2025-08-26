# NAT Detector

This is a simple and temporary module for detecting potential NAT (Network Address Translation) devices. It analyzes flow records for each IP address and flags those that show a high number of unique TTL values and source ports — a common indicator of NATed traffic.

## Parameters

- `field` (`str`): Name of the field containing the TTL value.  

## Detection Criteria

An IP address is flagged if:
- It has **5 or more** unique TTL values (excluding 0), and
- It has **500 or more** unique source ports (excluding 0)

If these thresholds are met, the IP is annotated as a potential NAT device.
