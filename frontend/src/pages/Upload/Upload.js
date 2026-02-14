import React, { useState, useEffect } from 'react';
import { Card, Typography, Upload as AntUpload, Button, message, Form, Select, Input, Progress, Alert } from 'antd';
import { UploadOutlined, CheckCircleOutlined, LoadingOutlined } from '@ant-design/icons';
import { apiService } from '../../services/api';

const { Title } = Typography;
const { Option } = Select;

const Upload = () => {
  const [fileList, setFileList] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus] = useState('');
  const [currentScanId, setCurrentScanId] = useState(null);
  const [form] = Form.useForm();

  const handleFileChange = (info) => {
    const { file, fileList: newFileList } = info;
    
    // Validate file type
    const isValidType = file.type === 'text/csv' || 
                       file.type === 'application/vnd.ms-excel' ||
                       file.name.endsWith('.csv') || 
                       file.name.endsWith('.xlsx');
    
    if (!isValidType) {
      message.error('Please upload a CSV or Excel file.');
      setFileList([]);
      return;
    }

    setFileList(newFileList);
  };

  const beforeUpload = () => {
    return false; // Prevent auto upload
  };

  const checkScanStatus = async (scanId) => {
    try {
      const response = await apiService.getDashboardData();
      const scan = response.recent_scans?.find(s => s.scan_id === scanId);
      
      if (scan) {
        if (scan.status === 'completed') {
          setUploadProgress(100);
          setUploadStatus('completed');
          setUploading(false);
          message.success(`File processed successfully! Scan ID: ${scanId}`);
          setFileList([]);
          form.resetFields();
          setCurrentScanId(null);
        } else if (scan.status === 'failed') {
          setUploadProgress(0);
          setUploadStatus('failed');
          setUploading(false);
          message.error(`Processing failed: ${scan.error_message || 'Unknown error'}`);
          setCurrentScanId(null);
        } else if (scan.status === 'processing') {
          // Estimate progress based on time elapsed
          const startTime = new Date(scan.started_at);
          const elapsed = Date.now() - startTime.getTime();
          const estimatedProgress = Math.min(90, Math.floor(elapsed / 1000) * 10); // 10% per second, max 90%
          setUploadProgress(estimatedProgress);
          setUploadStatus('processing');
          
          // Continue checking
          setTimeout(() => checkScanStatus(scanId), 2000);
        }
      }
    } catch (error) {
      console.error('Failed to check scan status:', error);
      setUploadStatus('error');
      setUploading(false);
    }
  };

  const handleSubmit = async () => {
    if (fileList.length === 0) {
      message.error('Please select a file to upload.');
      return;
    }

    try {
      setUploading(true);
      setUploadProgress(0);
      setUploadStatus('uploading');
      const values = await form.validateFields();
      
      // Simulate upload progress
      setUploadProgress(20);
      setUploadStatus('uploading');
      
      const response = await apiService.uploadFile(
        fileList[0].originFileObj || fileList[0], 
        values.scan_type, 
        values.scan_name
      );
      
      setUploadProgress(50);
      setUploadStatus('processing');
      setCurrentScanId(response.scan_id);
      
      message.info(`File uploaded! Processing scan ID: ${response.scan_id}`);
      
      // Start checking scan status
      setTimeout(() => checkScanStatus(response.scan_id), 1000);
      
    } catch (error) {
      console.error('Upload error:', error);
      message.error('Failed to upload file. Please try again.');
      setUploading(false);
      setUploadProgress(0);
      setUploadStatus('');
    }
  };

  const uploadProps = {
    name: 'file',
    multiple: false,
    accept: '.csv,.xlsx',
    beforeUpload: beforeUpload,
    onChange: handleFileChange,
    fileList,
    onRemove: () => setFileList([]),
  };

  return (
    <Card>
      <Title level={2}>Upload Vulnerability Data</Title>
      <p>Upload CSV or Excel files containing vulnerability scan results.</p>
      
      <Form form={form} layout="vertical" style={{ marginTop: 24 }}>
        <Form.Item
          label="Scan Type"
          name="scan_type"
          rules={[{ required: true, message: 'Please select a scan type' }]}
        >
          <Select placeholder="Select scan type">
            <Option value="wazuh">Wazuh</Option>
            <Option value="openvas">OpenVAS</Option>
            <Option value="manual">Manual</Option>
          </Select>
        </Form.Item>
        
        <Form.Item
          label="Scan Name (Optional)"
          name="scan_name"
        >
          <Input placeholder="Enter a name for this scan" />
        </Form.Item>
        
        <Form.Item label="File">
          <AntUpload {...uploadProps}>
            <Button icon={<UploadOutlined />}>Select File</Button>
          </AntUpload>
        </Form.Item>
        
        <Form.Item>
          <Button 
            type="primary" 
            onClick={handleSubmit}
            loading={uploading}
            disabled={fileList.length === 0}
          >
            Upload File
          </Button>
        </Form.Item>
      </Form>

      {/* Progress Indicator */}
      {uploading && (
        <Card style={{ marginTop: 16 }}>
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: 8 }}>
              {uploadStatus === 'completed' ? (
                <CheckCircleOutlined style={{ color: '#52c41a', marginRight: 8 }} />
              ) : (
                <LoadingOutlined style={{ color: '#1890ff', marginRight: 8 }} />
              )}
              <strong>
                {uploadStatus === 'uploading' && 'Uploading file...'}
                {uploadStatus === 'processing' && 'Processing file and retrieving EPSS scores...'}
                {uploadStatus === 'completed' && 'Processing completed!'}
                {uploadStatus === 'failed' && 'Processing failed'}
              </strong>
            </div>
            <Progress 
              percent={uploadProgress} 
              status={uploadStatus === 'failed' ? 'exception' : uploadStatus === 'completed' ? 'success' : 'active'}
              strokeColor={{
                '0%': '#108ee9',
                '100%': '#87d068',
              }}
            />
            {currentScanId && (
              <div style={{ marginTop: 8, fontSize: '12px', color: '#666' }}>
                Scan ID: {currentScanId}
              </div>
            )}
          </div>
          
          {uploadStatus === 'processing' && (
            <Alert
              message="EPSS Score Retrieval"
              description="We're currently retrieving EPSS (Exploit Prediction Scoring System) scores for the vulnerabilities in your file. This process may take a few moments as we fetch the latest data from the EPSS database."
              type="info"
              showIcon
              style={{ marginTop: 16 }}
            />
          )}
        </Card>
      )}
    </Card>
  );
};

export default Upload;