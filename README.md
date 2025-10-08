# iot-iout-validation-framework

A comprehensive multi-tiered validation framework for IoT to IoUT (Internet of Underwater Things) data quality assurance, supporting laboratory to real-world deployment scenarios.

# Data-Scoring

A Python Program for scoring the collected data sets and save the scores in CSV files to make it easier to compare the data sets

# Enhanced_Model Jupyter Notebook

An enhanced machine learning code for detecting Distributed Denial of Service (DDoS) attacks in IoT networks, with extensive robustness testing under various network noise conditions.

# Command to Run

Validation_Framework.py and Data_Scoring.py are separated program and need to run it with two different command

```bash
python Validation_Framework.py
python Data_Scoring.py

Run ALL in Enhanced_Model.ipynb
```

## System Requirements

- This program has only been tested under MacOS/Linux (ARM)

### Python Version

- Python 3.7 or higher

### Dependencies

```bash
pandas>=1.3.0
numpy>=1.21.0
matplotlib>=3.4.0
scikit-learn>=0.24.0
```

## Validation Principles

### 1. Data Completeness Validation

#### Missing Values Check

- **Metric**: Missing value percentage per column
- **Threshold**: Ideal < 5%
- **Penalty**: -10 points for any missing values

#### Duplicate Rows Detection

- **Metric**: Number of identical records
- **Threshold**: Ideal = 0
- **Penalty**: -5 points for duplicates

#### Infinite Values Detection

- **Metric**: Count of inf/-inf values
- **Handling**: Replace with column's max/min finite values
- **Penalty**: -15 points for infinite values

### 2. Network Flow Consistency Validation

#### Flow Rate Verification

```
Flow Byts/s = (TotLen Fwd Pkts + TotLen Bwd Pkts) / Flow Duration
```

- **Tolerance**: < 0.001 (floating-point precision)
- **Pass Rate**: > 95% required

#### Packet Length Statistics Consistency

```
Pkt Len Min ≤ Pkt Len Mean ≤ Pkt Len Max
```

#### Inter-Arrival Time (IAT) Consistency

```
Flow IAT Min ≤ Flow IAT Mean ≤ Flow IAT Max
```

### 3. Protocol Flags Validation

#### TCP Flags Check (Protocol = 6)

- All flag counts must be ≥ 0
- SYN-ACK pattern validation
- RST/FIN flag reasonableness

### 4. DDoS Attack Pattern Validation

#### Key Metrics Comparison (DDoS vs Benign)

- **Packet Rate Ratio**: Expected > 10x
- **Flow Duration**: Abnormally short or long
- **SYN Flag Count**: SYN Flood detection

### 5. Statistical Properties Validation

#### Outlier Detection (IQR Method)

```python
Q1 = 25th percentile
Q3 = 75th percentile
IQR = Q3 - Q1
Outlier boundaries = [Q1 - 1.5*IQR, Q3 + 1.5*IQR]
```

#### Skewness Analysis

- |Skewness| > 1 indicates significant skew

### 6. Underwater Environment Validation (IoUT Datasets)

#### Latency Increase Verification

- **Expected**: Underwater latency > 1.5x terrestrial latency
- **Physics**: Sound speed (1500 m/s) << Light speed (3×10⁸ m/s)

#### Bandwidth Reduction Verification

- **Expected**: Bandwidth reduction > 20%
- **Reason**: Underwater channel limitations

#### Environmental Variability

- **Metric**: Coefficient of Variation (CV) = σ/μ
- **Expected**: Underwater CV > 1.5x terrestrial CV

### 7. Quality Scoring System

| Score Range | Grade     | Data Quality    | Recommendation                     |
| ----------- | --------- | --------------- | ---------------------------------- |
| 90-100      | Excellent | High quality    | Ready for use                      |
| 70-89       | Good      | Minor issues    | Minimal preprocessing needed       |
| 50-69       | Fair      | Moderate issues | Significant preprocessing required |
| < 50        | Poor      | Major issues    | Consider recollecting data         |

#### Scoring Formula

```
Base Score = 100
Deductions:
- Missing values: -10 points
- Duplicate rows: -5 points
- Infinite values: -15 points
- Each consistency check < 95%: -5 points
Final Score = max(0, Base Score - Deductions)
```
