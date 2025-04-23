#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pandas as pd
import numpy as np
import logging
import os
from typing import Tuple, Dict, Optional

logger = logging.getLogger("data-utils")

def load_dataset(data_path: str) -> pd.DataFrame:
    """
    Load and validate the mobile security dataset.
    
    Parameters:
        data_path (str): Path to the data file (CSV)
    
    Returns:
        DataFrame: Loaded dataframe
    
    Raises:
        FileNotFoundError: If the data file is not found
        ValueError: If the data lacks required columns
    """
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data file not found: {data_path}")

    # Load the data
    df = pd.read_csv(data_path)

    # Check for required columns
    required_columns = [
        'Category',
        'Security_Practice_Used',
        'Vulnerability_Types',
        'Mitigation_Strategies',
        'Developer_Challenges',
        'Assessment_Tools_Used',
        'Improvement_Suggestions'
    ]

    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Data is missing required columns: {', '.join(missing_columns)}")

    return df

def preprocess_data(data_path: str) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """
    Preprocess the mobile security dataset.
    
    Parameters:
        data_path (str): Path to the data file (CSV)
    
    Returns:
        Tuple[DataFrame, Dict]: Processed dataframe and category map
    """
    logger.info(f"Processing data from {data_path}...")

    # Load the data
    df = load_dataset(data_path)

    # Display basic info
    logger.info(f"Original dataset shape: {df.shape}")

    # Handle missing values
    df = df.dropna()
    logger.info(f"Dataset shape after removing missing values: {df.shape}")

    # Process categories
    category_counts = df['Category'].value_counts()
    logger.info(f"Category distribution (top 5): \n{category_counts.head()}")

    # Create combined features for text representation
    df['combined_features'] = (
            df['Category'] + ' ' +
            df['Security_Practice_Used'] + ' ' +
            df['Vulnerability_Types'] + ' ' +
            df['Mitigation_Strategies'] + ' ' +
            df['Assessment_Tools_Used']
    )

    # Create category mapping
    category_map = {cat: i for i, cat in enumerate(df['Category'].unique())}
    df['category_id'] = df['Category'].map(category_map)

    return df, category_map

def get_category_vulnerabilities(data_df: pd.DataFrame) -> Dict[str, Dict[str, int]]:
    """
    Get the most common vulnerabilities for each category.
    
    Parameters:
        data_df (DataFrame): Processed dataframe
    
    Returns:
        Dict: Dictionary of vulnerabilities for each category with their frequencies
    """
    if data_df is None:
        return {}

    category_vulns = {}

    for category in data_df['Category'].unique():
        # Filter data by category
        category_data = data_df[data_df['Category'] == category]

        # Collect all vulnerabilities associated with this category
        all_vulnerabilities = []
        for vulns in category_data['Vulnerability_Types']:
            if pd.notna(vulns):
                all_vulnerabilities.extend([v.strip() for v in vulns.split(',')])

        # Count frequency of each vulnerability
        vuln_counts = {}
        for vuln in all_vulnerabilities:
            if vuln in vuln_counts:
                vuln_counts[vuln] += 1
            else:
                vuln_counts[vuln] = 1

        # Sort vulnerabilities by frequency
        sorted_vulns = {k: v for k, v in sorted(vuln_counts.items(), key=lambda item: item[1], reverse=True)}

        category_vulns[category] = sorted_vulns

    return category_vulns

def get_common_mitigations(data_df: pd.DataFrame, vulnerability: str) -> Dict[str, int]:
    """
    Get common mitigation strategies for a specific vulnerability.
    
    Parameters:
        data_df (DataFrame): Processed dataframe
        vulnerability (str): Name of the vulnerability
    
    Returns:
        Dict: Dictionary of mitigation strategies with their frequencies
    """
    if data_df is None:
        return {}

    # Filter data to find records containing the specified vulnerability
    vuln_data = data_df[data_df['Vulnerability_Types'].str.contains(vulnerability, na=False)]

    # Collect all mitigation strategies associated with this vulnerability
    all_mitigations = []
    for mits in vuln_data['Mitigation_Strategies']:
        if pd.notna(mits):
            all_mitigations.extend([m.strip() for m in mits.split(',')])

    # Count frequency of each strategy
    mit_counts = {}
    for mit in all_mitigations:
        if mit in mit_counts:
            mit_counts[mit] += 1
        else:
            mit_counts[mit] = 1

    # Sort strategies by frequency
    sorted_mits = {k: v for k, v in sorted(mit_counts.items(), key=lambda item: item[1], reverse=True)}

    return sorted_mits

def get_recommendations_for_category(data_df: pd.DataFrame, category: str) -> list:
    """
    Get improvement recommendations for a specific category.
    
    Parameters:
        data_df (DataFrame): Processed dataframe
        category (str): Application category
    
    Returns:
        list: List of improvement recommendations
    """
    if data_df is None:
        return []

    # Filter data by category
    category_data = data_df[data_df['Category'] == category]

    # Collect all recommendations associated with this category
    all_recommendations = []
    for recs in category_data['Improvement_Suggestions']:
        if pd.notna(recs):
            all_recommendations.append(recs.strip())

    # Remove duplicates
    unique_recommendations = list(set(all_recommendations))

    return unique_recommendations

def get_tool_usage_stats(data_df: pd.DataFrame) -> Dict[str, int]:
    """
    Get statistics on assessment tool usage.
    
    Parameters:
        data_df (DataFrame): Processed dataframe
    
    Returns:
        Dict: Dictionary of assessment tools with their usage frequency
    """
    if data_df is None:
        return {}

    # Collect all assessment tools
    all_tools = []
    for tools in data_df['Assessment_Tools_Used']:
        if pd.notna(tools):
            all_tools.extend([t.strip() for t in tools.split(',')])

    # Count frequency of each tool
    tool_counts = {}
    for tool in all_tools:
        if tool in tool_counts:
            tool_counts[tool] += 1
        else:
            tool_counts[tool] = 1

    # Sort tools by frequency
    sorted_tools = {k: v for k, v in sorted(tool_counts.items(), key=lambda item: item[1], reverse=True)}

    return sorted_tools

def export_analysis_results(data_df: pd.DataFrame, output_dir: str = "analysis_results") -> None:
    """
    Export data analysis results to CSV files.
    
    Parameters:
        data_df (DataFrame): Processed dataframe
        output_dir (str): Output directory
    """
    if data_df is None:
        logger.warning("Cannot export analysis results: Data not available")
        return

    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Export tool usage statistics
    tool_stats = get_tool_usage_stats(data_df)
    tool_df = pd.DataFrame(list(tool_stats.items()), columns=['Tool', 'Usage_Count'])
    tool_df.to_csv(os.path.join(output_dir, "tool_usage_stats.csv"), index=False)

    # Export vulnerabilities by category
    category_vulns = get_category_vulnerabilities(data_df)
    for category, vulns in category_vulns.items():
        if vulns:
            vuln_df = pd.DataFrame(list(vulns.items()), columns=['Vulnerability', 'Count'])
            safe_category = category.replace('/', '_').replace(' ', '_')
            vuln_df.to_csv(os.path.join(output_dir, f"{safe_category}_vulnerabilities.csv"), index=False)

    # Export application categories
    category_counts = data_df['Category'].value_counts()
    category_df = pd.DataFrame(category_counts).reset_index()
    category_df.columns = ['Category', 'Count']
    category_df.to_csv(os.path.join(output_dir, "category_distribution.csv"), index=False)

    logger.info(f"Analysis results exported to directory {output_dir}")