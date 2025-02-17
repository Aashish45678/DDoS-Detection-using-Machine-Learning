import pyshark
import numpy as np
import pandas as pd
from threading import Thread
from queue import Queue

# Process a single packet and update the flows dictionary
def process_packet(packet, flows):
    try:
        if not hasattr(packet, 'ip') or packet.transport_layer is None or not hasattr(packet, packet.transport_layer):
            return

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport
        protocol = packet.transport_layer
        timestamp = float(packet.sniff_timestamp)
        packet_length = int(packet.length)

        flags = getattr(packet.tcp, 'flags', None) if hasattr(packet, 'tcp') else None
        header_length = int(packet.tcp.hdr_len) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'hdr_len') else 0
        init_win_bytes_forward = int(packet.tcp.window_size_value) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'window_size_value') else 0
        min_seg_size_forward = int(packet.tcp.option_len) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'option_len') else 0

        psh_flag = 1 if flags and 'PSH' in flags else 0
        urg_flag = 1 if flags and 'URG' in flags else 0
        fin_flag = 1 if flags and 'FIN' in flags else 0
        syn_flag = 1 if flags and 'SYN' in flags else 0
        rst_flag = 1 if flags and 'RST' in flags else 0
        ack_flag = 1 if flags and 'ACK' in flags else 0
        cwe_flag = 1 if flags and 'CWE' in flags else 0
        ece_flag = 1 if flags and 'ECE' in flags else 0

        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        if flow_key not in flows:
            flows[flow_key] = {
                "timestamps": [],
                "lengths": [],
                "fwd_lengths": [],
                "bwd_lengths": [],
                "fwd_timestamps": [],
                "bwd_timestamps": [],
                "fwd_psh_flags": 0,
                "bwd_psh_flags": 0,
                "fwd_urg_flags": 0,
                "bwd_urg_flags": 0,
                "fwd_header_lengths": [],
                "bwd_header_lengths": [],
                "fin_flags": 0,
                "syn_flags": 0,
                "rst_flags": 0,
                "psh_flags": 0,
                "ack_flags": 0,
                "urg_flags": 0,
                "cwe_flags": 0,
                "ece_flags": 0,
                "init_win_bytes_forward": init_win_bytes_forward,
                "min_seg_size_forward": min_seg_size_forward,
            }

        flows[flow_key]["timestamps"].append(timestamp)
        flows[flow_key]["lengths"].append(packet_length)

        if src_ip < dst_ip:
            flows[flow_key]["fwd_lengths"].append(packet_length)
            flows[flow_key]["fwd_timestamps"].append(timestamp)
            flows[flow_key]["fwd_psh_flags"] += psh_flag
            flows[flow_key]["fwd_urg_flags"] += urg_flag
            flows[flow_key]["fwd_header_lengths"].append(header_length)
        else:
            flows[flow_key]["bwd_lengths"].append(packet_length)
            flows[flow_key]["bwd_timestamps"].append(timestamp)
            flows[flow_key]["bwd_psh_flags"] += psh_flag
            flows[flow_key]["bwd_urg_flags"] += urg_flag
            flows[flow_key]["bwd_header_lengths"].append(header_length)

        flows[flow_key]["fin_flags"] += fin_flag
        flows[flow_key]["syn_flags"] += syn_flag
        flows[flow_key]["rst_flags"] += rst_flag
        flows[flow_key]["psh_flags"] += psh_flag
        flows[flow_key]["ack_flags"] += ack_flag
        flows[flow_key]["urg_flags"] += urg_flag
        flows[flow_key]["cwe_flags"] += cwe_flag
        flows[flow_key]["ece_flags"] += ece_flag
    except AttributeError:
        return
    

# Worker function for processing packets
def worker(packet_queue, flows):
    while not packet_queue.empty():
        try:
            packet = packet_queue.get()
            process_packet(packet, flows)
            print(f"Processed packet from queue. Remaining: {packet_queue.qsize()}")
            packet_queue.task_done()
        except Exception as e:
            print(f"Error processing packet: {e}")


# Main function with threading
def calculate_features_with_threading(pcap_file, num_threads=8):
    try:
        cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        return None

    packet_queue = Queue()
    flows = {}

    for packet in cap:
        packet_queue.put(packet)

    threads = []
    for _ in range(num_threads):
        thread = Thread(target=worker, args=(packet_queue, flows))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
        
    features_list = []
    # Compute Flow-Level Features
    for flow_key, flow_data in flows.items():
        timestamps = np.array(flow_data["timestamps"])
        fwd_timestamps = np.array(flow_data["fwd_timestamps"])
        bwd_timestamps = np.array(flow_data["bwd_timestamps"])
        lengths = np.array(flow_data["lengths"])
        fwd_lengths = np.array(flow_data["fwd_lengths"])
        bwd_lengths = np.array(flow_data["bwd_lengths"])
        fwd_header_lengths = np.array(flow_data["fwd_header_lengths"])
        bwd_header_lengths = np.array(flow_data["bwd_header_lengths"])

        flow_duration = (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0

        flow_iat = np.diff(timestamps) if len(timestamps) > 1 else np.array([0])
        fwd_iat = np.diff(fwd_timestamps) if len(fwd_timestamps) > 1 else np.array([0])
        bwd_iat = np.diff(bwd_timestamps) if len(bwd_timestamps) > 1 else np.array([0])
        
        # Bulk feature placeholders (no bulk rate context in this script, set to 0)
        fwd_avg_bytes_bulk = 0
        fwd_avg_packets_bulk = 0
        fwd_avg_bulk_rate = 0
        bwd_avg_bytes_bulk = 0
        bwd_avg_packets_bulk = 0
        bwd_avg_bulk_rate = 0
        
         # Compute Active and Idle Times
        inter_arrival_times = np.diff(timestamps) if len(timestamps) > 1 else np.array([0])
        active_times = inter_arrival_times[inter_arrival_times < 1]  # Threshold to define "active"
        idle_times = inter_arrival_times[inter_arrival_times >= 1]  # Threshold to define "idle"

        flow_features = {
            "src_ip": flow_key[0],
            "dst_ip": flow_key[1],
            "src_port": flow_key[2],
            "Destination Port": flow_key[3],
            "protocol": flow_key[4],
            "Flow Duration": flow_duration,
            
            # Total Packets and Lengths
            "Total Fwd Packets": len(fwd_lengths),
            "Total Backward Packets": len(bwd_lengths),
            "Total Length of Fwd Packets": fwd_lengths.sum(),
            "Total Length of Bwd Packets": bwd_lengths.sum(),

            # Packet Length Stats
            "Fwd Packet Length Max": fwd_lengths.max() if len(fwd_lengths) > 0 else 0,
            "Fwd Packet Length Min": fwd_lengths.min() if len(fwd_lengths) > 0 else 0,
            "Fwd Packet Length Mean": fwd_lengths.mean() if len(fwd_lengths) > 0 else 0,
            "Fwd Packet Length Std": fwd_lengths.std() if len(fwd_lengths) > 0 else 0,
            "Bwd Packet Length Max": bwd_lengths.max() if len(bwd_lengths) > 0 else 0,
            "Bwd Packet Length Min": bwd_lengths.min() if len(bwd_lengths) > 0 else 0,
            "Bwd Packet Length Mean": bwd_lengths.mean() if len(bwd_lengths) > 0 else 0,
            "Bwd Packet Length Std": bwd_lengths.std() if len(bwd_lengths) > 0 else 0,

            # Flow Metrics
            "Flow Bytes/s": lengths.sum() / flow_duration if flow_duration > 0 else 0,
            "Flow Packets/s": len(lengths) / flow_duration if flow_duration > 0 else 0,
            
            # Flow IAT Features
            "Flow IAT Mean": flow_iat.mean() if len(flow_iat) > 0 else 0,
            "Flow IAT Std": flow_iat.std() if len(flow_iat) > 0 else 0,
            "Flow IAT Max": flow_iat.max() if len(flow_iat) > 0 else 0,
            "Flow IAT Min": flow_iat.min() if len(flow_iat) > 0 else 0,

            # Fwd IAT Features
            "Fwd IAT Total": fwd_iat.sum() if len(fwd_iat) > 0 else 0,
            "Fwd IAT Mean": fwd_iat.mean() if len(fwd_iat) > 0 else 0,
            "Fwd IAT Std": fwd_iat.std() if len(fwd_iat) > 0 else 0,
            "Fwd IAT Max": fwd_iat.max() if len(fwd_iat) > 0 else 0,
            "Fwd IAT Min": fwd_iat.min() if len(fwd_iat) > 0 else 0,

            # Bwd IAT Features
            "Bwd IAT Total": bwd_iat.sum() if len(bwd_iat) > 0 else 0,
            "Bwd IAT Mean": bwd_iat.mean() if len(bwd_iat) > 0 else 0,
            "Bwd IAT Std": bwd_iat.std() if len(bwd_iat) > 0 else 0,
            "Bwd IAT Max": bwd_iat.max() if len(bwd_iat) > 0 else 0,
            "Bwd IAT Min": bwd_iat.min() if len(bwd_iat) > 0 else 0,
            
            #flags
            
            "Fwd PSH Flags": flow_data["fwd_psh_flags"],
            "Bwd PSH Flags": flow_data["bwd_psh_flags"],
            "Fwd URG Flags": flow_data["fwd_urg_flags"],
            "Bwd URG Flags": flow_data["bwd_urg_flags"],
            
             # Header Lengths
            "Fwd Header Length": fwd_header_lengths.sum(),
            "Bwd Header Length": bwd_header_lengths.sum(),
            
            # Flow Metrics
            "Fwd Packets/s": len(fwd_lengths) / flow_duration if flow_duration > 0 else 0,
            "Bwd Packets/s": len(bwd_lengths) / flow_duration if flow_duration > 0 else 0,
            
            # Packet Length Stats
            "Min Packet Length": lengths.min() if len(lengths) > 0 else 0,
            "Max Packet Length": lengths.max() if len(lengths) > 0 else 0,
            "Packet Length Mean": lengths.mean() if len(lengths) > 0 else 0,
            "Packet Length Std": lengths.std() if len(lengths) > 0 else 0,
            "Packet Length Variance": lengths.var() if len(lengths) > 0 else 0,
            
            # Flags
            "FIN Flag Count": flow_data["fin_flags"],
            "SYN Flag Count": flow_data["syn_flags"],
            "RST Flag Count": flow_data["rst_flags"],
            "PSH Flag Count": flow_data["psh_flags"],
            "ACK Flag Count": flow_data["ack_flags"],
            "URG Flag Count": flow_data["urg_flags"],
            "CWE Flag Count": flow_data["cwe_flags"],
            "ECE Flag Count": flow_data["ece_flags"],

            # Down/Up Ratio
            "Down/Up Ratio": (len(bwd_lengths) / len(fwd_lengths)) if len(fwd_lengths) > 0 else 0,

            # Average Packet Size
            "Average Packet Size": lengths.sum() / len(lengths) if len(lengths) > 0 else 0,

            # Average Forward/Backward Segment Size
            "Avg Fwd Segment Size": fwd_lengths.mean() if len(fwd_lengths) > 0 else 0,
            "Avg Bwd Segment Size": bwd_lengths.mean() if len(bwd_lengths) > 0 else 0,
            
            # Bulk Metrics
            "Fwd Avg Bytes/Bulk": fwd_avg_bytes_bulk,
            "Fwd Avg Packets/Bulk": fwd_avg_packets_bulk,
            "Fwd Avg Bulk Rate": fwd_avg_bulk_rate,
            "Bwd Avg Bytes/Bulk": bwd_avg_bytes_bulk,
            "Bwd Avg Packets/Bulk": bwd_avg_packets_bulk,
            "Bwd Avg Bulk Rate": bwd_avg_bulk_rate,
            
            # Subflow Metrics
            "Subflow Fwd Packets": len(fwd_lengths),
            "Subflow Fwd Bytes": fwd_lengths.sum(),
            "Subflow Bwd Packets": len(bwd_lengths),
            "Subflow Bwd Bytes": bwd_lengths.sum(),

            # Initial Window Sizes
            "Init_Win_bytes_forward": flow_data["init_win_bytes_forward"],
            "Init_Win_bytes_backward": 0,  # Placeholder as no context for backward window size

            # Active Data Packets Forward
            "act_data_pkt_fwd": len(fwd_lengths),

            # Minimum Segment Size Forward
            "min_seg_size_forward": flow_data["min_seg_size_forward"],

             # Active Features
            "Active Mean": active_times.mean() if len(active_times) > 0 else 0,
            "Active Std": active_times.std() if len(active_times) > 0 else 0,
            "Active Max": active_times.max() if len(active_times) > 0 else 0,
            "Active Min": active_times.min() if len(active_times) > 0 else 0,

            # Idle Features
            "Idle Mean": idle_times.mean() if len(idle_times) > 0 else 0,
            "Idle Std": idle_times.std() if len(idle_times) > 0 else 0,
            "Idle Max": idle_times.max() if len(idle_times) > 0 else 0,
            "Idle Min": idle_times.min() if len(idle_times) > 0 else 0,
        }

        features_list.append(flow_features)
    
    # Convert to DataFrame and Save
    features_df = pd.DataFrame(features_list)
    features_df.to_csv("./attack01_demo44.csv", index=False)
    return features_df
        
        
    
# pcap_file = "./new/newddos.pcap"
# features_df = calculate_features_with_threading(pcap_file, num_threads=8)

if __name__ == "__main__":
    # Example usage for testing
    pcap_file = "../../DDoS Attack using LOIC/newddos.pcap"
    try:
        features_df = calculate_features_with_threading(pcap_file, num_threads=8)
        print(features_df.head())
    except Exception as e:
        print(f"Error opening pcap file: {e}")
