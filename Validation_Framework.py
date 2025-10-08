import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os



class DDoSValidationFramework:
    def __init__(self, data_set_name, data_set_path):
        self.data_set_name = data_set_name
        self.data_set_path = data_set_path
        self.df = None
        self.validation_results = {}

    def load_data(self):
        try:
            self.df = pd.read_csv(self.data_set_path)
            print(f"Data loaded successfully from {self.data_set_path}")
            print(f"Dataset shape: {self.df.shape}")

            # Data cleaning: replace infinite values
            numeric_columns = self.df.select_dtypes(include=[np.number]).columns
            for col in numeric_columns:
                # Replace positive infinity with the maximum finite value of the column
                if np.isinf(self.df[col]).any():
                    max_finite = self.df[col][np.isfinite(self.df[col])].max()
                    self.df[col].replace([np.inf], max_finite, inplace=True)

                # Replace negative infinity with the minimum finite value of the column
                if np.isneginf(self.df[col]).any():
                    min_finite = self.df[col][np.isfinite(self.df[col])].min()
                    self.df[col].replace([-np.inf], min_finite, inplace=True)
                    
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
        
    def validate_completeness(self):
        print("\nValidating data completeness...\n")
        
        # Check for missing values in the dataset
        missing_stats = {
            'total_missing': self.df.isnull().sum().sum(),
            'missing_by_column': self.df.isnull().sum()[self.df.isnull().sum() > 0].to_dict(),
            'missing_percentage': (self.df.isnull().sum() / len(self.df) * 100).round(2).to_dict()
        }
        
        # check duplicates
        duplicate_rows = self.df.duplicated().sum()
        
        # check infinite values
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns
        inf_count = 0
        inf_columns = {}
        for col in numeric_cols:
            inf_in_col = np.isinf(self.df[col]).sum()
            if inf_in_col > 0:
                inf_columns[col] = inf_in_col
                inf_count += inf_in_col
        
        #check data types
        expected_types = {
            'Flow ID': 'object',
            'Src IP': 'object',
            'Dst IP': 'object',
            'Protocol': 'int64',
            'Flow Duration': 'int64',
            'Tot Fwd Pkts': 'int64',
            'Tot Bwd Pkts': 'int64',
            'Label': 'object'
        }
        
        missmatched_types = {}
        for column, expected_type in expected_types.items():
            if column in self.df.columns:
                actual_type = str(self.df[column].dtype)
                if actual_type != expected_type:
                    missmatched_types[column] = (actual_type, expected_type)
                    
        self.validation_results['completeness'] = {
            'missing_stats': missing_stats,
            'duplicate_rows': duplicate_rows,
            'infinite_values': inf_count,
            'infinite_columns': inf_columns,
            'missmatched_types': missmatched_types
        }
        
        # Print summary
        print(f"Total missing values: {missing_stats['total_missing']}")
        print(f"Duplicate rows: {duplicate_rows}")
        print(f"Infinite values: {inf_count}")
        if inf_columns:
            print(f"Columns with infinite values: {list(inf_columns.keys())}")

        return self.validation_results['completeness']
    
    def validate_flow_consistency(self):
        print("\nValidating flow consistency...\n")
        
        consistency_checks = {}
        
        # 1. verify total packet counts
        if all(col in self.df.columns for col in ['Tot Fwd Pkts', 'Tot Bwd Pkts']):
            total_pkts_check = (self.df['Tot Fwd Pkts'] >= 0) & (self.df['Tot Bwd Pkts'] >= 0)
            consistency_checks['valid_packet_counts'] = total_pkts_check.sum() / len(self.df)
            print(f"Valid packet counts: {consistency_checks['valid_packet_counts']:.2%}")
        
        # 2. verify flow duration
        if 'Flow Duration' in self.df.columns:
            valid_duration = self.df['Flow Duration'] >= 0
            consistency_checks['valid_flow_duration'] = valid_duration.sum() / len(self.df)
            print(f"Valid flow duration: {consistency_checks['valid_flow_duration']:.2%}")
        
        # 3. verify flow rate calculation
        if all(col in self.df.columns for col in ['Flow Byts/s', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Flow Duration']):
            # avoid division by zero errors
            valid_flows = self.df['Flow Duration'] > 0
            if valid_flows.sum() > 0:
                calculated_rate = (self.df.loc[valid_flows, 'TotLen Fwd Pkts'] + 
                                 self.df.loc[valid_flows, 'TotLen Bwd Pkts']) / self.df.loc[valid_flows, 'Flow Duration']

                # allow a certain margin of error (floating point calculation)
                rate_diff = abs(calculated_rate - self.df.loc[valid_flows, 'Flow Byts/s'])
                consistent_rate = rate_diff < 1e-3  # tolerance
                consistency_checks['flow_rate_consistency'] = consistent_rate.sum() / len(valid_flows)
                print(f"Flow rate calculation consistency: {consistency_checks['flow_rate_consistency']:.2%}")

        # 4. verify packet length statistics
        if all(col in self.df.columns for col in ['Pkt Len Min', 'Pkt Len Mean', 'Pkt Len Max']):
            valid_pkt_len = ((self.df['Pkt Len Min'] <= self.df['Pkt Len Mean']) & 
                           (self.df['Pkt Len Mean'] <= self.df['Pkt Len Max']))
            consistency_checks['packet_length_consistency'] = valid_pkt_len.sum() / len(self.df)
            print(f"Packet length statistics consistency: {consistency_checks['packet_length_consistency']:.2%}")

        # 5. verify IAT (Inter-Arrival Time) consistency
        if all(col in self.df.columns for col in ['Flow IAT Min', 'Flow IAT Mean', 'Flow IAT Max']):
            valid_iat = ((self.df['Flow IAT Min'] <= self.df['Flow IAT Mean']) & 
                        (self.df['Flow IAT Mean'] <= self.df['Flow IAT Max']))
            consistency_checks['iat_consistency'] = valid_iat.sum() / len(self.df)
            print(f"IAT statistics consistency: {consistency_checks['iat_consistency']:.2%}")

        self.validation_results['flow_consistency'] = consistency_checks
        return consistency_checks
    
    def validate_protocol_flags(self):
        print("\nValidating protocol flags...\n")
        flag_validation = {}

        # TCP flag validation
        tcp_flags = ['FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 
                     'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt']
        
        if all(col in self.df.columns for col in tcp_flags):
            # Check TCP flows (Protocol = 6)
            tcp_flows = self.df[self.df['Protocol'] == 6] if 'Protocol' in self.df.columns else self.df

            # Validate flag counts are non-negative
            for flag in tcp_flags:
                valid_flags = (tcp_flows[flag] >= 0).sum() / len(tcp_flows)
                flag_validation[f'{flag}_valid'] = valid_flags

            # Validate common TCP handshake patterns
            # SYN-ACK pattern validation
            syn_ack_pattern = tcp_flows[(tcp_flows['SYN Flag Cnt'] > 0) &
                                       (tcp_flows['ACK Flag Cnt'] > 0)]
            flag_validation['syn_ack_pattern_ratio'] = len(syn_ack_pattern) / len(tcp_flows) if len(tcp_flows) > 0 else 0

            print(f"TCP flag validation results:")
            for key, value in flag_validation.items():
                print(f"  {key}: {value:.2%}")

        self.validation_results['protocol_flags'] = flag_validation
        return flag_validation
    
    def validate_ddos_patterns(self):
        print("\nValidating DDoS attack patterns...\n")

        if 'Label' not in self.df.columns:
            print("Warning: 'Label' column is not present in the dataset.")
            return None
        
        ddos_validation = {}

        # Separate DDoS and benign traffic
        ddos_flows = self.df[self.df['Label'].str.contains('DDoS', case=False, na=False)]
        benign_flows = self.df[self.df['Label'].str.contains('BENIGN', case=False, na=False)]
        
        ddos_validation['ddos_count'] = len(ddos_flows)
        ddos_validation['benign_count'] = len(benign_flows)
        ddos_validation['ddos_ratio'] = len(ddos_flows) / len(self.df) if len(self.df) > 0 else 0
        
        print(f"DDoS Count: {ddos_validation['ddos_count']}")
        print(f"Benign Count: {ddos_validation['benign_count']}")
        print(f"DDoS Ratio: {ddos_validation['ddos_ratio']:.2%}")

        # Validate DDoS features
        if len(ddos_flows) > 0 and len(benign_flows) > 0:
            # 1. Packet rate comparison
            if 'Flow Pkts/s' in self.df.columns:
                ddos_pkt_rate = ddos_flows['Flow Pkts/s'].mean()
                benign_pkt_rate = benign_flows['Flow Pkts/s'].mean()

                # Avoid division by zero and handle extreme values
                if benign_pkt_rate > 0:
                    ratio = ddos_pkt_rate / benign_pkt_rate
                    # Cap the ratio at a reasonable maximum
                    ddos_validation['pkt_rate_ratio'] = min(ratio, 1000)
                else:
                    ddos_validation['pkt_rate_ratio'] = 1000 if ddos_pkt_rate > 0 else 1
                    
                print(f"DDoS/Benign Packet Rate Ratio: {ddos_validation['pkt_rate_ratio']:.2f}")

            # 2. Flow duration comparison
            if 'Flow Duration' in self.df.columns:
                ddos_duration = ddos_flows['Flow Duration'].mean()
                benign_duration = benign_flows['Flow Duration'].mean()
                
                if benign_duration > 0:
                    ratio = ddos_duration / benign_duration
                    ddos_validation['duration_ratio'] = min(ratio, 1000)
                else:
                    ddos_validation['duration_ratio'] = 1000 if ddos_duration > 0 else 1
                    
                print(f"DDoS/Benign Flow Duration Ratio: {ddos_validation['duration_ratio']:.2f}")

            # 3. SYN flag comparison (SYN Flood detection)
            if 'SYN Flag Cnt' in self.df.columns:
                ddos_syn = ddos_flows['SYN Flag Cnt'].mean()
                benign_syn = benign_flows['SYN Flag Cnt'].mean()
                
                if benign_syn > 0:
                    ratio = ddos_syn / benign_syn
                    ddos_validation['syn_ratio'] = min(ratio, 1000)
                else:
                    ddos_validation['syn_ratio'] = 1000 if ddos_syn > 0 else 1
                    
                print(f"DDoS/Benign SYN Flag Ratio: {ddos_validation['syn_ratio']:.2f}")

        self.validation_results['ddos_patterns'] = ddos_validation
        return ddos_validation
    
    def validate_statistical_properties(self):
        print("\nValidating statistical properties...\n")
        
        statistical_validation = {}

        # choose numeric features for statistical validation
        numeric_features = self.df.select_dtypes(include=[np.number]).columns
        
        # 1. outlier ratio detection by IQR method
        outlier_percentages = {}
        for feature in numeric_features[:10]:  # only check first 10 numeric features
            # Ensure no infinite values
            finite_values = self.df[feature][np.isfinite(self.df[feature])]
            if len(finite_values) > 0:
                Q1 = finite_values.quantile(0.25)
                Q3 = finite_values.quantile(0.75)
                IQR = Q3 - Q1
                outliers = ((finite_values < (Q1 - 1.5 * IQR)) | 
                           (finite_values > (Q3 + 1.5 * IQR))).sum()
                outlier_percentages[feature] = outliers / len(self.df) * 100
        
        statistical_validation['outlier_percentages'] = outlier_percentages

        # 2. skewness detection
        skewness_values = {}
        for feature in numeric_features[:10]:
            finite_values = self.df[feature][np.isfinite(self.df[feature])]
            if len(finite_values) > 0:
                skew = finite_values.skew()
                skewness_values[feature] = skew
        
        statistical_validation['skewness'] = skewness_values
        
        # print results
        print("Outlier Ratios (First 10 Features):")
        for feature, percentage in outlier_percentages.items():
            if percentage > 5:  # only show features with outliers > 5%
                print(f"  {feature}: {percentage:.2f}%")

        print("\nSkewness (First 10 Features):")
        for feature, skew in skewness_values.items():
            if abs(skew) > 1:  # only show features with skewness > 1
                print(f"  {feature}: {skew:.2f}")
        
        self.validation_results['statistical_properties'] = statistical_validation
        return statistical_validation
    
    def generate_validation_plots(self):
        print("\nGenerating validation plots...\n")

        # Create Report directory if it doesn't exist
        os.makedirs('Report', exist_ok=True)
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle(f'{self.data_set_name} Data Quality Validation Report', fontsize=16)

        # 1. Missing Values Heatmap
        ax1 = axes[0, 0]
        missing_data = self.df.isnull().sum()[self.df.isnull().sum() > 0]
        if len(missing_data) > 0:
            missing_data.plot(kind='bar', ax=ax1)
            ax1.set_title('Missing Values Count by Feature')
            ax1.set_xlabel('Feature')
            ax1.set_ylabel('Missing Values Count')
        else:
            ax1.text(0.5, 0.5, 'No Missing Values', ha='center', va='center', transform=ax1.transAxes)
            ax1.set_title('Missing Values Check')

        # 2. Label Distribution
        ax2 = axes[0, 1]
        if 'Label' in self.df.columns:
            label_counts = self.df['Label'].value_counts()
            label_counts.plot(kind='pie', ax=ax2, autopct='%1.1f%%')
            ax2.set_title('Label Distribution')
            ax2.set_ylabel('')

        # 3. Flow Duration Distribution
        ax3 = axes[1, 0]
        if 'Flow Duration' in self.df.columns:
            # Use log scale for better visibility
            flow_duration = self.df['Flow Duration'][(self.df['Flow Duration'] > 0) & 
                                                    (np.isfinite(self.df['Flow Duration']))]
            if len(flow_duration) > 0:
                ax3.hist(np.log10(flow_duration + 1), bins=50, edgecolor='black')
                ax3.set_title('Flow Duration Distribution (log10)')
                ax3.set_xlabel('log10(Flow Duration + 1)')
                ax3.set_ylabel('Frequency')

        # 4. Packet Rate Comparison (DDoS vs Benign)
        ax4 = axes[1, 1]
        if 'Label' in self.df.columns and 'Flow Pkts/s' in self.df.columns:
            # Clean data by removing infinite values
            ddos_data = self.df[self.df['Label'].str.contains('DDoS', case=False, na=False)]['Flow Pkts/s']
            benign_data = self.df[self.df['Label'].str.contains('BENIGN', case=False, na=False)]['Flow Pkts/s']

            # Filter out infinite values and NaN
            ddos_data_clean = ddos_data[np.isfinite(ddos_data)].dropna()
            benign_data_clean = benign_data[np.isfinite(benign_data)].dropna()

            # Use boxplot for comparison
            if len(ddos_data_clean) > 0 and len(benign_data_clean) > 0:
                data_to_plot = [benign_data_clean, ddos_data_clean]
                ax4.boxplot(data_to_plot, labels=['Benign', 'DDoS'])
                ax4.set_title('Packet Rate Comparison')
                ax4.set_ylabel('Flow Pkts/s')
                ax4.set_yscale('log')  # Use log scale

        plt.tight_layout()
        # Save to Report directory
        output_path = os.path.join('Report', f'{self.data_set_name}_validation_report.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Validation plot saved to: {output_path}")
        plt.show()
        
        return fig
    
    def generate_summary_report(self):
        print("\n=== Summary Report ===")
        print(f"Dataset: {self.data_set_name}")
        print(f"Total Rows: {len(self.df)}")
        print(f"Total Columns: {len(self.df.columns)}")

        # Calculate overall quality score
        quality_score = 100

        # Penalty items
        if self.validation_results.get('completeness', {}).get('missing_stats', {}).get('total_missing', 0) > 0:
            quality_score -= 10

        if self.validation_results.get('completeness', {}).get('duplicate_rows', 0) > 0:
            quality_score -= 5
            
        if self.validation_results.get('completeness', {}).get('infinite_values', 0) > 0:
            quality_score -= 15

        flow_consistency = self.validation_results.get('flow_consistency', {})
        for check, ratio in flow_consistency.items():
            if ratio < 0.95:  # If consistency is below 95%
                quality_score -= 5

        print(f"\nData Quality Score: {max(0, quality_score)}/100")

        # Create Report directory if it doesn't exist
        os.makedirs('Report', exist_ok=True)
        
        # Generate detailed text report
        report_path = os.path.join('Report', f'{self.data_set_name}_validation_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"Data Quality Validation Report - {self.data_set_name}\n")
            f.write("=" * 50 + "\n\n")

            for section, data in self.validation_results.items():
                f.write(f"{section.upper()}\n")
                f.write("-" * 30 + "\n")
                f.write(str(data) + "\n\n")

        print(f"Detailed report saved to: {report_path}")

        return max(0, quality_score)
    
    def run_full_validation(self):
        """Run full validation process"""
        if not self.load_data():
            return None
        
        self.validate_completeness()
        self.validate_flow_consistency()
        self.validate_protocol_flags()
        self.validate_ddos_patterns()
        self.validate_statistical_properties()
        self.generate_validation_plots()
        quality_score = self.generate_summary_report()
        
        return self.validation_results, quality_score


class CrossDatasetValidator:
    """Cross-dataset validation class"""

    def __init__(self, datasets):
        """
        Initialize cross-dataset validator

        Args:
            datasets: Dictionary in the format {dataset_name: dataset_path}
        """
        self.datasets = datasets
        self.loaded_data = {}
        
    def load_all_datasets(self):
        """Load all datasets"""
        for name, path in self.datasets.items():
            try:
                df = pd.read_csv(path)

                # Clean infinite values
                numeric_columns = df.select_dtypes(include=[np.number]).columns
                for col in numeric_columns:
                    if np.isinf(df[col]).any():
                        # Replace infinite values with NaN, then can choose to fill or drop
                        df[col].replace([np.inf, -np.inf], np.nan, inplace=True)
                        # Fill with the max/min finite value of the column
                        if df[col].notna().any():
                            max_val = df[col].max()
                            df[col].fillna(max_val, inplace=True)
                
                self.loaded_data[name] = df
                print(f"Loaded {name}: {df.shape}")
            except Exception as e:
                print(f"Failed to load {name}: {e}")

    def compare_feature_distributions(self, feature_name):
        """Compare the distribution of a specific feature across different datasets"""
        # Create Report directory if it doesn't exist
        os.makedirs('Report', exist_ok=True)
        
        plt.figure(figsize=(15, 5))
        
        n_datasets = len(self.loaded_data)
        for i, (name, df) in enumerate(self.loaded_data.items()):
            if feature_name in df.columns:
                plt.subplot(1, n_datasets, i+1)
                
                # get finite values for the feature
                data = df[feature_name]
                finite_data = data[np.isfinite(data)].dropna()
                
                if len(finite_data) > 0:
                    # Plot histogram of finite values
                    finite_data.hist(bins=50, alpha=0.7, edgecolor='black')
                    plt.title(f'{name}\n{feature_name}')
                    plt.xlabel(feature_name)
                    plt.ylabel('Frequency')

                    # Add statistical information
                    plt.text(0.05, 0.95, f'Mean: {finite_data.mean():.2f}\nStd: {finite_data.std():.2f}',
                            transform=plt.gca().transAxes, verticalalignment='top',
                            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
                else:
                    plt.text(0.5, 0.5, 'No valid data', ha='center', va='center', 
                            transform=plt.gca().transAxes)
                    plt.title(f'{name}\n{feature_name}')

        plt.tight_layout()
        # Save to Report directory
        output_path = os.path.join('Report', f'cross_dataset_{feature_name.replace("/", "_")}_distribution.png')
        plt.savefig(output_path, dpi=300)
        print(f"Cross-dataset comparison plot saved to: {output_path}")
        plt.show()
    
    def statistical_comparison(self):
        """Statistical comparison across different datasets"""
        comparison_results = {}

        # Select common numeric features
        common_features = None
        for name, df in self.loaded_data.items():
            numeric_cols = set(df.select_dtypes(include=[np.number]).columns)
            if common_features is None:
                common_features = numeric_cols
            else:
                common_features = common_features.intersection(numeric_cols)

        # Perform statistical comparison for each common feature
        for feature in list(common_features)[:10]:  # Compare only the first 10 features
            feature_stats = {}
            for name, df in self.loaded_data.items():
                # Only use finite values for statistics
                finite_values = df[feature][np.isfinite(df[feature])]
                if len(finite_values) > 0:
                    feature_stats[name] = {
                        'mean': finite_values.mean(),
                        'std': finite_values.std(),
                        'median': finite_values.median(),
                        'min': finite_values.min(),
                        'max': finite_values.max(),
                        'inf_count': np.isinf(df[feature]).sum()
                    }
            comparison_results[feature] = feature_stats
        
        # Generate comparison report
        print("\n=== Cross-dataset Statistical Comparison (First 10 Features) ===")
        for feature, stats in comparison_results.items():
            print(f"\n{feature}:")
            for dataset, values in stats.items():
                print(f"  {dataset}:")
                print(f"    Mean: {values['mean']:.2f}, Std: {values['std']:.2f}")
                if values['inf_count'] > 0:
                    print(f"    Infinite values: {values['inf_count']}")
        
        return comparison_results
    
    def validate_model_consistency(self):
        """Validate model consistency across different datasets"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score
        from sklearn.preprocessing import StandardScaler
        
        results = {}

        # Select common features
        common_features = ['Tot Fwd Pkts', 'Tot Bwd Pkts', 'Flow Duration', 
                          'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean']
        
        for name, df in self.loaded_data.items():
            if 'Label' not in df.columns:
                continue

            # Prepare data
            available_features = [f for f in common_features if f in df.columns]
            if len(available_features) < 3:
                continue
                
            X = df[available_features].copy()

            # Handle infinite and missing values
            X.replace([np.inf, -np.inf], np.nan, inplace=True)
            X.fillna(X.mean(), inplace=True)
            
            y = df['Label'].apply(lambda x: 1 if 'DDoS' in str(x) else 0)

            # Split train and test sets
            try:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.3, random_state=42, stratify=y
                )

                # Standardize features
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)

                # Train model
                rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
                rf.fit(X_train_scaled, y_train)

                # Predict and evaluate
                y_pred = rf.predict(X_test_scaled)
                
                results[name] = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred, zero_division=0),
                    'recall': recall_score(y_test, y_pred, zero_division=0),
                    'feature_importance': dict(zip(available_features, rf.feature_importances_))
                }
            except Exception as e:
                print(f"Error processing {name}: {e}")
                continue

        print("\n=== Model Consistency Validation ===")
        for name, metrics in results.items():
            print(f"\n{name}:")
            print(f"  Accuracy: {metrics['accuracy']:.4f}")
            print(f"  Precision: {metrics['precision']:.4f}")
            print(f"  Recall: {metrics['recall']:.4f}")
            print(f"  Top features:")
            sorted_features = sorted(metrics['feature_importance'].items(), 
                                   key=lambda x: x[1], reverse=True)
            for feat, importance in sorted_features[:3]:
                print(f"    {feat}: {importance:.3f}")

        return results
    
    def generate_comparison_report(self, model_results=None):
        """Generate a comprehensive comparison report"""
        # create Report directory if it doesn't exist
        os.makedirs('Report', exist_ok=True)
        
        report_path = os.path.join('Report', 'cross_dataset_comparison_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Cross-Dataset Comparison Report\n")
            f.write("=" * 50 + "\n\n")
            
            # Dataset overview
            f.write("DATASET OVERVIEW\n")
            f.write("-" * 30 + "\n")
            for name, df in self.loaded_data.items():
                f.write(f"\n{name}:\n")
                f.write(f"  Shape: {df.shape}\n")
                f.write(f"  Memory usage: {df.memory_usage().sum() / 1024**2:.2f} MB\n")
                if 'Label' in df.columns:
                    label_counts = df['Label'].value_counts()
                    f.write(f"  Labels:\n")
                    for label, count in label_counts.items():
                        f.write(f"    {label}: {count} ({count/len(df)*100:.1f}%)\n")
            
            # Statistical comparison results
            if hasattr(self, 'comparison_results'):
                f.write("\n\nSTATISTICAL COMPARISON\n")
                f.write("-" * 30 + "\n")
                # Write comparison results here
            
            # Model consistency results
            if model_results:
                f.write("\n\nMODEL CONSISTENCY RESULTS\n")
                f.write("-" * 30 + "\n")
                for name, metrics in model_results.items():
                    f.write(f"\n{name}:\n")
                    f.write(f"  Accuracy: {metrics['accuracy']:.4f}\n")
                    f.write(f"  Precision: {metrics['precision']:.4f}\n")
                    f.write(f"  Recall: {metrics['recall']:.4f}\n")
        
        print(f"\nCross-dataset comparison report saved to: {report_path}")


# Usage example
if __name__ == "__main__":
    # Single dataset validation
    print("Validate In-Lab IoT Dataset")
    validator_iot = DDoSValidationFramework('InLab_IoT', 'Data_Set/inlab_iot_combined.csv')
    lab_iot_report, lab_iot_score = validator_iot.run_full_validation()
    
    print("\n" + "="*50 + "\n")

    # Validate other datasets
    print("Validate In-Lab IoUT Dataset")
    validator_iout = DDoSValidationFramework('InLab_IoUT', 'Data_Set/inlab_iout_combined.csv')
    lab_iout_report, lab_iout_score = validator_iout.run_full_validation()

    print("\n" + "="*50 + "\n")
    
    print("Validate Real World IoUT Dataset 1M")
    validator_iout = DDoSValidationFramework('Real_1M_World_IoUT', 'Data_Set/real_world_ddos_1m.csv')
    real_1_iout_report, real_1_iout_score = validator_iout.run_full_validation()
    
    print("\n" + "="*50 + "\n")

    print("Validate Merged_final_IoT DDOS Dataset")
    validator_iout = DDoSValidationFramework('Merged_final_IoTMerged_final_IoT_DDoS', 'Data_Set/Merged_final_IoT_DDoS_Dataset.csv')
    real_1_5_iout_report, real_1_5iout_score = validator_iout.run_full_validation()

    print("\n" + "="*50 + "\n")
    
    print("Validate Merged_final_IoUT_70cm")
    validator_iout = DDoSValidationFramework('Merged_final_IoUT_70cm', 'Data_Set/Merged_final_IoUT_70cm.csv')
    real_1_iout_report, real_1_iout_score = validator_iout.run_full_validation()
    
    print("\n" + "="*50 + "\n")

    print("Validate Merged_final_IoUT_shallow")
    validator_iout = DDoSValidationFramework('Merged_final_IoUT_shallow', 'Data_Set/Merged_final_IoUT_shallow.csv')
    real_muddy_iout_report, real_muddy_iout_score = validator_iout.run_full_validation()
    
    # Cross-dataset validation
    print("=== Cross-dataset Validation ===")
    datasets = {
        'InLab_IoT': 'Data_Set/inlab_iot_combined.csv',
        'InLab_IoUT': 'Data_Set/inlab_iout_combined.csv',
        'RealWorld_1.5M': 'Data_Set/real_world_ddos_1.5m.csv',
        'RealWorld_1M': 'Data_Set/real_world_ddos_1m.csv',
        'RealWorld_Muddy': 'Data_Set/real_world_ddos_seashore_muddy.csv',
        'Merged_final_IoT_DDoS': 'Data_Set/Merged_final_IoT_DDoS_Dataset.csv',
        'Merged_final_IoUT_70cm': 'Data_Set/Merged_final_IoUT_70cm.csv',
        'Merged_final_IoUT_shallow': 'Data_Set/Merged_final_IoUT_shallow.csv'
    }
    
    cross_validator = CrossDatasetValidator(datasets)
    cross_validator.load_all_datasets()

    # Compare feature distributions
    try:
        cross_validator.compare_feature_distributions('Flow Duration')
        cross_validator.compare_feature_distributions('Flow Pkts/s')
    except Exception as e:
        print(f"Error in feature distribution comparison: {e}")

    # Statistical comparison
    cross_validator.statistical_comparison()

    # Model consistency validation
    cross_validator.validate_model_consistency()