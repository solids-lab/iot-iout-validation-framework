import pandas as pd
import numpy as np
import os
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')


class DataQualityScorer:
    """Class for scoring data quality of the Dataset"""
    
    def __init__(self, output_dir='Report'):
        """Pointing the output file to the specified directory"""
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
    def load_and_clean_dataset(self, filepath):
        try:
            df = pd.read_csv(filepath)
            
            # Clean infinite values
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            for col in numeric_cols:
                if np.isinf(df[col]).any():
                    # Get finite values
                    finite_vals = df[col][np.isfinite(df[col])]
                    if len(finite_vals) > 0:
                        max_finite = finite_vals.max()
                        min_finite = finite_vals.min()
                        # Replace positive infinity with max finite value
                        df.loc[df[col] == np.inf, col] = max_finite
                        # Replace negative infinity with min finite value
                        df.loc[df[col] == -np.inf, col] = min_finite
            
            return df
        except Exception as e:
            print(f"Error loading {filepath}: {e}")
            return None
    
    def calculate_quality_score(self, df, dataset_name, dataset_type):
        '''        Calculate the quality score of the dataset based on various validation checks'''
        base_score = 100
        deductions = 0
        
        quality_report = {
            'dataset_name': dataset_name,
            'dataset_type': dataset_type,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_rows': len(df),
            'total_columns': len(df.columns)
        }
        
        
        # Missing Values Check (Penalty: -10 points for any missing values)
        missing_values = df.isnull().sum().sum()
        missing_percentage = (missing_values / (len(df) * len(df.columns))) * 100
        quality_report['missing_values_count'] = missing_values
        quality_report['missing_values_percentage'] = round(missing_percentage, 2)
        
        if missing_values > 0:
            deductions += 10  
            quality_report['missing_values_penalty'] = -10
        else:
            quality_report['missing_values_penalty'] = 0
        
        # Duplicate Rows Detection (Penalty: -5 points for duplicates)
        duplicate_rows = df.duplicated().sum()
        duplicate_percentage = (duplicate_rows / len(df)) * 100
        quality_report['duplicate_rows'] = duplicate_rows
        quality_report['duplicate_percentage'] = round(duplicate_percentage, 2)
        
        if duplicate_rows > 0:
            deductions += 5  
            quality_report['duplicate_rows_penalty'] = -5
        else:
            quality_report['duplicate_rows_penalty'] = 0
        
        # Infinite Values Detection (Penalty: -15 points for infinite values)
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        inf_values = 0
        for col in numeric_cols:
            inf_values += np.isinf(df[col]).sum()
        
        quality_report['infinite_values'] = inf_values
        
        if inf_values > 0:
            deductions += 15 
            quality_report['infinite_values_penalty'] = -15
        else:
            quality_report['infinite_values_penalty'] = 0
        
        # flow consistency checks
        consistency_failures = 0
        
        # Flow Rate Verification
        if all(col in df.columns for col in ['Flow Byts/s', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Flow Duration']):
            valid_flows = df['Flow Duration'] > 0
            if valid_flows.sum() > 0:
                calculated_rate = (df.loc[valid_flows, 'TotLen Fwd Pkts'] + 
                                 df.loc[valid_flows, 'TotLen Bwd Pkts']) / df.loc[valid_flows, 'Flow Duration']
                rate_diff = abs(calculated_rate - df.loc[valid_flows, 'Flow Byts/s'])
                consistent_rate = (rate_diff < 0.001).sum() / len(valid_flows) * 100  # Tolerance
                quality_report['flow_rate_consistency'] = round(consistent_rate, 2)
                
                if consistent_rate < 95:  
                    consistency_failures += 1
        else:
            quality_report['flow_rate_consistency'] = 'N/A'
        
        # Packet Length Statistics Consistency
        if all(col in df.columns for col in ['Pkt Len Min', 'Pkt Len Mean', 'Pkt Len Max']):
            pkt_len_consistent = ((df['Pkt Len Min'] <= df['Pkt Len Mean']) & 
                                (df['Pkt Len Mean'] <= df['Pkt Len Max'])).sum() / len(df) * 100
            quality_report['packet_length_consistency'] = round(pkt_len_consistent, 2)
            
            if pkt_len_consistent < 95:
                consistency_failures += 1
        else:
            quality_report['packet_length_consistency'] = 'N/A'
        
        # Inter-Arrival Time (IAT) Consistency
        if all(col in df.columns for col in ['Flow IAT Min', 'Flow IAT Mean', 'Flow IAT Max']):
            iat_consistent = ((df['Flow IAT Min'] <= df['Flow IAT Mean']) & 
                            (df['Flow IAT Mean'] <= df['Flow IAT Max'])).sum() / len(df) * 100
            quality_report['iat_consistency'] = round(iat_consistent, 2)
            
            if iat_consistent < 95:
                consistency_failures += 1
        else:
            quality_report['iat_consistency'] = 'N/A'
        
        # Total packet counts validity
        if all(col in df.columns for col in ['Tot Fwd Pkts', 'Tot Bwd Pkts']):
            valid_packets = ((df['Tot Fwd Pkts'] >= 0) & (df['Tot Bwd Pkts'] >= 0)).sum() / len(df) * 100
            quality_report['valid_packet_counts'] = round(valid_packets, 2)
            
            if valid_packets < 95:
                consistency_failures += 1
        else:
            quality_report['valid_packet_counts'] = 'N/A'
        
        # Flow duration validity
        if 'Flow Duration' in df.columns:
            valid_duration = (df['Flow Duration'] >= 0).sum() / len(df) * 100
            quality_report['valid_flow_duration'] = round(valid_duration, 2)
            
            if valid_duration < 95:
                consistency_failures += 1
        else:
            quality_report['valid_flow_duration'] = 'N/A'
        
        # Apply consistency penalty: -5 points for each check < 95%
        consistency_penalty = consistency_failures * 5
        deductions += consistency_penalty
        quality_report['consistency_failures'] = consistency_failures
        quality_report['consistency_penalty'] = -consistency_penalty
        
        # Protocol Flags Validation
        tcp_flag_issues = 0
        
        if 'Protocol' in df.columns:
            tcp_flows = df[df['Protocol'] == 6]  # TCP Protocol = 6
            
            tcp_flags = ['FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 
                        'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt']
            
            if len(tcp_flows) > 0 and all(col in df.columns for col in tcp_flags):
                for flag in tcp_flags:
                    # All flag counts must be >= 0
                    invalid_flags = (tcp_flows[flag] < 0).sum()
                    if invalid_flags > 0:
                        tcp_flag_issues += 1
                
                # SYN-ACK pattern validation
                syn_ack_pattern = tcp_flows[(tcp_flows['SYN Flag Cnt'] > 0) &
                                           (tcp_flows['ACK Flag Cnt'] > 0)]
                syn_ack_ratio = len(syn_ack_pattern) / len(tcp_flows) * 100
                quality_report['syn_ack_pattern_ratio'] = round(syn_ack_ratio, 2)
            else:
                quality_report['syn_ack_pattern_ratio'] = 'N/A'
        else:
            quality_report['syn_ack_pattern_ratio'] = 'N/A'
        
        quality_report['tcp_flag_issues'] = tcp_flag_issues
        
        # DDoS Traffic Patterns Validation
        
        if 'Label' in df.columns:
            # Separate DDoS and benign traffic
            ddos_flows = df[df['Label'].str.contains('DDoS', case=False, na=False)]
            benign_flows = df[df['Label'].str.contains('BENIGN', case=False, na=False)]
            
            quality_report['ddos_count'] = len(ddos_flows)
            quality_report['benign_count'] = len(benign_flows)
            quality_report['ddos_ratio'] = round(len(ddos_flows) / len(df) * 100, 2) if len(df) > 0 else 0
            
            # Key Metrics Comparison (DDoS vs Benign)
            if len(ddos_flows) > 0 and len(benign_flows) > 0:
                # Packet Rate Ratio (Expected > 10x)
                if 'Flow Pkts/s' in df.columns:
                    ddos_pkt_rate = ddos_flows['Flow Pkts/s'].mean()
                    benign_pkt_rate = benign_flows['Flow Pkts/s'].mean()
                    
                    if benign_pkt_rate > 0:
                        pkt_rate_ratio = ddos_pkt_rate / benign_pkt_rate
                        quality_report['ddos_benign_pkt_rate_ratio'] = round(pkt_rate_ratio, 2)
                    else:
                        quality_report['ddos_benign_pkt_rate_ratio'] = 'N/A'
                else:
                    quality_report['ddos_benign_pkt_rate_ratio'] = 'N/A'
                
                # Flow Duration comparison
                if 'Flow Duration' in df.columns:
                    ddos_duration = ddos_flows['Flow Duration'].mean()
                    benign_duration = benign_flows['Flow Duration'].mean()
                    
                    if benign_duration > 0:
                        duration_ratio = ddos_duration / benign_duration
                        quality_report['ddos_benign_duration_ratio'] = round(duration_ratio, 2)
                    else:
                        quality_report['ddos_benign_duration_ratio'] = 'N/A'
                else:
                    quality_report['ddos_benign_duration_ratio'] = 'N/A'
                
                # SYN Flag Count (SYN Flood detection)
                if 'SYN Flag Cnt' in df.columns:
                    ddos_syn = ddos_flows['SYN Flag Cnt'].mean()
                    benign_syn = benign_flows['SYN Flag Cnt'].mean()
                    
                    if benign_syn > 0:
                        syn_ratio = ddos_syn / benign_syn
                        quality_report['ddos_benign_syn_ratio'] = round(syn_ratio, 2)
                    else:
                        quality_report['ddos_benign_syn_ratio'] = 'N/A'
                else:
                    quality_report['ddos_benign_syn_ratio'] = 'N/A'
            else:
                quality_report['ddos_benign_pkt_rate_ratio'] = 'N/A'
                quality_report['ddos_benign_duration_ratio'] = 'N/A'
                quality_report['ddos_benign_syn_ratio'] = 'N/A'
        else:
            quality_report['ddos_count'] = 'N/A'
            quality_report['benign_count'] = 'N/A'
            quality_report['ddos_ratio'] = 'N/A'
            quality_report['ddos_benign_pkt_rate_ratio'] = 'N/A'
            quality_report['ddos_benign_duration_ratio'] = 'N/A'
            quality_report['ddos_benign_syn_ratio'] = 'N/A'
        
        # STATISTICAL PROPERTIES VALIDATION
        
        # Outlier Detection using IQR Method
        outlier_features = []
        highly_skewed_features = []
        
        # Sample first 10 numeric columns for efficiency
        sample_cols = list(numeric_cols)[:10]
        
        for col in sample_cols:
            finite_vals = df[col][np.isfinite(df[col])]
            if len(finite_vals) > 0:
                # IQR-based outlier detection 
                Q1 = finite_vals.quantile(0.25)
                Q3 = finite_vals.quantile(0.75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 1.5 * IQR
                upper_bound = Q3 + 1.5 * IQR
                
                outliers = ((finite_vals < lower_bound) | (finite_vals > upper_bound)).sum()
                outlier_percentage = (outliers / len(df)) * 100
                
                if outlier_percentage > 10:  # Significant outliers
                    outlier_features.append(col)
                
                # Skewness Analysis (|Skewness| > 1 indicates significant skew)
                try:
                    skewness = finite_vals.skew()
                    if abs(skewness) > 1:
                        highly_skewed_features.append(col)
                except:
                    pass
        
        quality_report['significant_outlier_features'] = len(outlier_features)
        quality_report['highly_skewed_features'] = len(highly_skewed_features)
        
        # Underwater/IOT Specific Metrics
        if 'IoUT' in dataset_type or 'Underwater' in dataset_type:
            # Check for environmental variability (CV = σ/μ)
            if 'Flow Duration' in df.columns:
                flow_dur_std = df['Flow Duration'].std()
                flow_dur_mean = df['Flow Duration'].mean()
                if flow_dur_mean > 0:
                    cv = flow_dur_std / flow_dur_mean
                    quality_report['flow_duration_cv'] = round(cv, 4)
                else:
                    quality_report['flow_duration_cv'] = 'N/A'
            else:
                quality_report['flow_duration_cv'] = 'N/A'
                
            if 'Flow IAT Mean' in df.columns:
                iat_mean = df['Flow IAT Mean'].mean()
                quality_report['mean_iat_underwater'] = round(iat_mean, 4)
            else:
                quality_report['mean_iat_underwater'] = 'N/A'
        
        # Final Scoring Calculation
        final_score = max(0, base_score - deductions)
        
        quality_report['base_score'] = base_score
        quality_report['total_deductions'] = deductions
        quality_report['final_score'] = final_score
        
        if final_score >= 90:
            grade = 'Excellent'
            data_quality = 'High quality'
            recommendation = 'Ready for use'
        elif final_score >= 70:
            grade = 'Good'
            data_quality = 'Minor issues'
            recommendation = 'Minimal preprocessing needed'
        elif final_score >= 50:
            grade = 'Fair'
            data_quality = 'Moderate issues'
            recommendation = 'Significant preprocessing required'
        else:
            grade = 'Poor'
            data_quality = 'Major issues'
            recommendation = 'Consider recollecting data'
        
        quality_report['grade'] = grade
        quality_report['data_quality'] = data_quality
        quality_report['recommendation'] = recommendation
        
        return quality_report
    
    def batch_process_datasets(self, datasets_info):
        """
        Process all datasets and generate a single CSV report
        """
        all_reports = []
        
        print("\n" + "="*70)
        print("IoT/IoUT DDoS Dataset Quality Assessment")
        print("Based on Multi-Tiered Validation Framework")
        print("="*70 + "\n")
        print("Processing all datasets...")
        print("-" * 70)
        
        for i, (filepath, name, dtype) in enumerate(datasets_info, 1):
            print(f"[{i}/{len(datasets_info)}] Processing: {name}... ", end='')
            
            # Load and clean dataset
            df = self.load_and_clean_dataset(filepath)
            
            if df is not None:
                # Calculate quality score
                report = self.calculate_quality_score(df, name, dtype)
                
                # Create flattened report for CSV
                flat_report = {
                    'Dataset Name': report['dataset_name'],
                    'Dataset Type': report['dataset_type'],
                    'Total Rows': report['total_rows'],
                    'Total Columns': report['total_columns'],
                    
                    # Data Completeness
                    'Missing Values Count': report['missing_values_count'],
                    'Missing Values %': report['missing_values_percentage'],
                    'Missing Penalty': report['missing_values_penalty'],
                    'Duplicate Rows': report['duplicate_rows'],
                    'Duplicate %': report['duplicate_percentage'],
                    'Duplicate Penalty': report['duplicate_rows_penalty'],
                    'Infinite Values': report['infinite_values'],
                    'Infinite Penalty': report['infinite_values_penalty'],
                    
                    # Flow Consistency
                    'Flow Rate Consistency %': report.get('flow_rate_consistency', 'N/A'),
                    'Packet Length Consistency %': report.get('packet_length_consistency', 'N/A'),
                    'IAT Consistency %': report.get('iat_consistency', 'N/A'),
                    'Valid Packet Counts %': report.get('valid_packet_counts', 'N/A'),
                    'Valid Flow Duration %': report.get('valid_flow_duration', 'N/A'),
                    'Consistency Failures': report['consistency_failures'],
                    'Consistency Penalty': report['consistency_penalty'],
                    
                    # Protocol Flags
                    'TCP Flag Issues': report.get('tcp_flag_issues', 0),
                    'SYN-ACK Pattern Ratio %': report.get('syn_ack_pattern_ratio', 'N/A'),
                    
                    # DDoS Patterns
                    'DDoS Count': report.get('ddos_count', 'N/A'),
                    'Benign Count': report.get('benign_count', 'N/A'),
                    'DDoS Ratio %': report.get('ddos_ratio', 'N/A'),
                    'DDoS/Benign Packet Rate Ratio': report.get('ddos_benign_pkt_rate_ratio', 'N/A'),
                    'DDoS/Benign Duration Ratio': report.get('ddos_benign_duration_ratio', 'N/A'),
                    'DDoS/Benign SYN Ratio': report.get('ddos_benign_syn_ratio', 'N/A'),
                    
                    # Statistical Properties
                    'Outlier Features': report['significant_outlier_features'],
                    'Skewed Features': report['highly_skewed_features'],
                    
                    # Final Scores
                    'Base Score': report['base_score'],
                    'Total Deductions': report['total_deductions'],
                    'Final Score': report['final_score'],
                    'Grade': report['grade'],
                    'Data Quality': report['data_quality'],
                    'Recommendation': report['recommendation']
                }
                
                # Add IoUT specific metrics if applicable
                if 'IoUT' in dtype:
                    flat_report['Flow Duration CV'] = report.get('flow_duration_cv', 'N/A')
                    flat_report['Mean IAT Underwater'] = report.get('mean_iat_underwater', 'N/A')
                
                all_reports.append(flat_report)
                print(f"Done (Score: {report['final_score']}/100)")
            else:
                print("Failed to load")
        
        # Create DataFrame
        report_df = pd.DataFrame(all_reports)
        
        # Save to CSV
        csv_path = os.path.join(self.output_dir, 'ddos_data_quality_scores.csv')
        report_df.to_csv(csv_path, index=False)
        
        print("-" * 70)
        print(f"\nQuality assessment completed.")
        print(f"Results saved to: {csv_path}")
        
        # Print summary
        if len(all_reports) > 0:
            print("\nSummary Statistics:")
            print(f"  Total datasets processed: {len(all_reports)}")
            print(f"  Average quality score: {report_df['Final Score'].mean():.1f}/100")
            print(f"  Highest score: {report_df['Final Score'].max()}/100")
            print(f"  Lowest score: {report_df['Final Score'].min()}/100")
            
            print("\nGrade Distribution:")
            grade_counts = report_df['Grade'].value_counts()
            for grade in ['Excellent', 'Good', 'Fair', 'Poor']:
                count = grade_counts.get(grade, 0)
                print(f"  {grade}: {count} dataset(s)")
        
        print("="*70)
        
        return report_df


def main():
    """Main function to run the data quality scorer"""
    
    # Initialize the scorer
    scorer = DataQualityScorer(output_dir='Report')
    
    # Define all datasets to evaluate
    datasets_to_evaluate = [
        ('Data_Set/inlab_iot_combined.csv', 'In-Lab IoT Dataset', 'In-Lab IoT'),
        ('Data_Set/inlab_iout_combined.csv', 'In-Lab IoUT Dataset', 'In-Lab IoUT'),
        ('Data_Set/real_world_ddos_1m.csv', 'Real-World IoUT 1M', 'Real-World IoUT'),
        ('Data_Set/real_world_ddos_1.5m.csv', 'Real-World IoUT 1.5M', 'Real-World IoUT'),
        ('Data_Set/real_world_ddos_seashore_muddy.csv', 'Real-World IoUT Seashore Muddy', 'Real-World IoUT'),
        ('Data_Set/Merged_final_IoT_DDoS_Dataset.csv', 'Merged Final IoT DDoS', 'Merged IoT'),
        ('Data_Set/Merged_final_IoUT_70cm.csv', 'Merged Final IoUT 70cm', 'Merged IoUT'),
        ('Data_Set/Merged_final_IoUT_shallow.csv', 'Merged Final IoUT Shallow', 'Merged IoUT')
    ]
    
    # Process all datasets and generate report
    quality_df = scorer.batch_process_datasets(datasets_to_evaluate)
    
    return quality_df


if __name__ == "__main__":
    # Run the main function
    results = main()