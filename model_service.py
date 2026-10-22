import joblib
import pandas as pd
import numpy as np
import random
import os

class NIDSPredictor:
    def __init__(self, model_path):
        if not os.path.exists(model_path):
            print(f"Warning: {model_path} not found. Mock predictions will be used if model is absent.")
            self.model = None
        else:
            try:
                self.model = joblib.load(model_path)
                print("Model loaded successfully.")
            except Exception as e:
                print(f"Error loading model: {e}")
                self.model = None

        # Feature order required by the model
        self.features = [
            'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
            'Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets', 'Fwd_Packet_Length_Max',
            'Fwd_Packet_Length_Min', 'Fwd_Packet_Length_Mean', 'Fwd_Packet_Length_Std',
            'Bwd_Packet_Length_Max', 'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
            'Bwd_Packet_Length_Std', 'Flow_Bytes/s', 'Flow_Packets/s', 'Flow_IAT_Mean',
            'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean',
            'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total', 'Bwd_IAT_Mean',
            'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Fwd_PSH_Flags', 'Bwd_PSH_Flags',
            'Fwd_URG_Flags', 'Bwd_URG_Flags', 'Fwd_Header_Length', 'Bwd_Header_Length',
            'Fwd_Packets/s', 'Bwd_Packets/s', 'Min_Packet_Length', 'Max_Packet_Length',
            'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance', 'FIN_Flag_Count',
            'SYN_Flag_Count', 'RST_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count',
            'URG_Flag_Count', 'CWE_Flag_Count', 'ECE_Flag_Count', 'Down/Up_Ratio',
            'Average_Packet_Size', 'Avg_Fwd_Segment_Size', 'Avg_Bwd_Segment_Size',
            'Fwd_Header_Length.1', 'Fwd_Avg_Bytes/Bulk', 'Fwd_Avg_Packets/Bulk',
            'Fwd_Avg_Bulk_Rate', 'Bwd_Avg_Bytes/Bulk', 'Bwd_Avg_Packets/Bulk',
            'Bwd_Avg_Bulk_Rate', 'Subflow_Fwd_Packets', 'Subflow_Fwd_Bytes',
            'Subflow_Bwd_Packets', 'Subflow_Bwd_Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min', 'Idle_Mean',
            'Idle_Std', 'Idle_Max', 'Idle_Min'
        ]

    def generate_mock_flow(self):
        """Generates random data ensuring it aligns with the 78 expected NIDS features."""
        is_anomaly = random.random() > 0.85
        flow_data = {}
        for feature in self.features:
            if is_anomaly:
                flow_data[feature] = [float(np.random.normal(500, 200))]
            else:
                flow_data[feature] = [float(np.random.normal(50, 20))]
            if flow_data[feature][0] < 0:
                 flow_data[feature][0] = 0.0
        return pd.DataFrame(flow_data)

    def generate_flow(self, dest_port, bytes_transfer, attack_type=None):
        """Generates flow features for the classifier, matching either standard traffic or attack simulations."""
        flow_data = {}
        
        # Determine features based on simulation type
        if attack_type == 'ddos':
            # DDoS attacks typically have high forward packet rates and specific ports
            for feature in self.features:
                if feature == 'Destination_Port':
                    flow_data[feature] = [float(dest_port)]
                elif feature in ['Total_Length_of_Fwd_Packets', 'Subflow_Fwd_Bytes']:
                    flow_data[feature] = [float(np.random.normal(5000, 1000))]
                elif feature in ['Total_Fwd_Packets', 'Subflow_Fwd_Packets']:
                    flow_data[feature] = [float(np.random.normal(100, 20))]
                elif 'Mean' in feature or 'Std' in feature or 'Max' in feature:
                    flow_data[feature] = [float(np.random.normal(1000, 300))]
                else:
                    flow_data[feature] = [float(np.random.normal(500, 100))]
        elif attack_type == 'portscan':
            # PortScan typically has very short flow durations and minimal payload
            for feature in self.features:
                if feature == 'Destination_Port':
                    flow_data[feature] = [float(dest_port)]
                elif feature in ['Flow_Duration', 'Flow_IAT_Mean', 'Flow_IAT_Max', 'Flow_IAT_Min']:
                    flow_data[feature] = [float(random.uniform(0.1, 5.0))]
                elif feature in ['Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets']:
                    flow_data[feature] = [float(random.randint(0, 40))]
                elif feature in ['Total_Fwd_Packets', 'Total_Backward_Packets']:
                    flow_data[feature] = [1.0]
                else:
                    flow_data[feature] = [0.0]
        elif attack_type == 'bruteforce':
            # Brute force login attempts on SSH/FTP (ports 22/21)
            for feature in self.features:
                if feature == 'Destination_Port':
                    flow_data[feature] = [float(dest_port)]
                elif feature in ['Flow_Duration', 'Fwd_IAT_Total']:
                    flow_data[feature] = [float(np.random.normal(100000, 20000))]
                elif feature in ['Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets']:
                    flow_data[feature] = [float(np.random.normal(1500, 300))]
                elif feature in ['Total_Fwd_Packets', 'Total_Backward_Packets']:
                    flow_data[feature] = [float(np.random.normal(15, 3))]
                else:
                    flow_data[feature] = [float(np.random.normal(100, 20))]
        else:
            # Normal connection (Class 0 / Benign)
            for feature in self.features:
                if feature == 'Destination_Port':
                    flow_data[feature] = [float(dest_port)]
                elif feature in ['Total_Length_of_Fwd_Packets', 'Subflow_Fwd_Bytes']:
                    flow_data[feature] = [float(bytes_transfer)]
                else:
                    flow_data[feature] = [float(np.random.normal(50, 10))]
                
        # Make sure no values are negative
        for feature in self.features:
            if flow_data[feature][0] < 0:
                flow_data[feature][0] = 0.0

        return pd.DataFrame(flow_data)

    def predict(self, df):
        if self.model is None:
            # Fallback mock prediction if model is missing
            return 0 if random.random() > 0.15 else 1, 0.85 + random.uniform(0, 0.14)
        
        try:
            prediction = self.model.predict(df)[0]
            
            # Predict probabilities if supported
            if hasattr(self.model, 'predict_proba'):
                probs = self.model.predict_proba(df)[0]
                confidence = max(probs)
            else:
                confidence = 0.95
                
            return prediction, confidence
        except Exception as e:
            print(f"Prediction Error: {e}")
            return 0, 0.0
