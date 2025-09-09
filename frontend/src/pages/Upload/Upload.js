import React, { useState } from 'react';
import { Card, Upload, Button, Form, Select, Input, message, Progress, List, Typography, Space, Tag } from 'antd';
import { InboxOutlined, UploadOutlined, FileTextOutlined, CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons';
import { useMutation, useQuery } from 'react-query';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { apiService } from '../../services/api';

const { Dragger } = Upload;
const { Option } = Select;
const { Text, Title } = Typography;

const UploadContainer = styled.div`
  .upload-section {
    margin-bottom: ${props => props.theme.spacing.xl};
  }

  .upload-form {
    .ant-form-item {
      margin-bottom: ${props => props.theme.spacing.lg};
    }
  }

  .scan-status {
    .ant-list-item {
      padding: ${props => props.theme.spacing.md};
      border-radius: ${props => props.theme.borderRadius.md};
      margin-bottom: ${props => props.theme.spacing.sm};
    }
  }
`;

const UploadCard = styled(Card)`
  .ant-upload-drag {
    border: 2px dashed ${props => props.theme.colors.border};
    border-radius: ${props => props.theme.borderRadius.md};
    background: ${props => props.theme.colors.background};
    transition: all 0.3s ease;

    &:hover {
      border-color: ${props => props.theme.colors.primary};
      background: ${props => props.theme.colors.surface};
    }
  }

  .ant-upload-drag-icon {
    color: ${props => props.theme.colors.primary};
    font-size: 48px;
  }

  .ant-upload-text {
    color: ${props => props.theme.colors.text};
    font-size: ${props => props.theme.typography.fontSize.lg};
    font-weight: ${props => props.theme.typography.fontWeight.medium};
  }

  .ant-upload-hint {
    color: ${props => props.theme.colors.textSecondary};
  }
`;

const Upload = () => {
  const [form] = Form.useForm();
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);

  // Fetch recent scans
  const { data: scans, refetch: refetchScans } = useQuery(
    'scans',
    apiService.getScans,
    {
      refetchInterval: 5000, // Refetch every 5 seconds to check scan status
    }
  );

  // Upload mutation
  const uploadMutation = useMutation(apiService.uploadCSV, {
    onSuccess: (data) => {
      message.success('File uploaded successfully! Processing in background...');
      form.resetFields();
      setUploading(false);
      setUploadProgress(0);
      refetchScans();
    },
    onError: (error) => {
      message.error(`Upload failed: ${error.message}`);
      setUploading(false);
      setUploadProgress(0);
    },
  });

  const handleUpload = async (file, values) => {
    setUploading(true);
    setUploadProgress(0);

    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      await uploadMutation.mutateAsync({
        file,
        scan_type: values.scan_type,
        scan_name: values.scan_name,
      });

      clearInterval(progressInterval);
      setUploadProgress(100);
    } catch (error) {
      clearInterval(progressInterval);
      throw error;
    }
  };

  const customRequest = async ({ file, onSuccess, onError }) => {
    try {
      const values = await form.validateFields();
      await handleUpload(file, values);
      onSuccess();
    } catch (error) {
      onError(error);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'processing':
        return 'processing';
      case 'failed':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircleOutlined />;
      case 'processing':
        return <FileTextOutlined />;
      case 'failed':
        return <CloseCircleOutlined />;
      default:
        return <FileTextOutlined />;
    }
  };

  return (
    <UploadContainer>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Title level={2}>Upload Vulnerability Data</Title>
        <Text type="secondary">
          Upload CSV files from Wazuh or OpenVAS vulnerability scanners
        </Text>
      </motion.div>

      <div className="upload-section">
        <UploadCard>
          <Form
            form={form}
            layout="vertical"
            className="upload-form"
            initialValues={{
              scan_type: 'wazuh',
            }}
          >
            <Form.Item
              name="scan_type"
              label="Scanner Type"
              rules={[{ required: true, message: 'Please select scanner type' }]}
            >
              <Select placeholder="Select scanner type">
                <Option value="wazuh">Wazuh</Option>
                <Option value="openvas">OpenVAS</Option>
              </Select>
            </Form.Item>

            <Form.Item
              name="scan_name"
              label="Scan Name (Optional)"
            >
              <Input placeholder="Enter a name for this scan" />
            </Form.Item>

            <Form.Item
              name="file"
              label="CSV File"
              rules={[{ required: true, message: 'Please upload a CSV file' }]}
            >
              <Dragger
                name="file"
                multiple={false}
                accept=".csv"
                customRequest={customRequest}
                disabled={uploading}
                showUploadList={false}
              >
                <p className="ant-upload-drag-icon">
                  <InboxOutlined />
                </p>
                <p className="ant-upload-text">
                  Click or drag CSV file to this area to upload
                </p>
                <p className="ant-upload-hint">
                  Support for single CSV file upload. Maximum file size: 50MB
                </p>
              </Dragger>
            </Form.Item>

            {uploading && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
              >
                <Progress
                  percent={uploadProgress}
                  status={uploadProgress === 100 ? 'success' : 'active'}
                  strokeColor={{
                    '0%': '#108ee9',
                    '100%': '#87d068',
                  }}
                />
              </motion.div>
            )}
          </Form>
        </UploadCard>
      </div>

      {/* Recent Scans */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card title="Recent Scans" className="scan-status">
          <List
            dataSource={scans?.scans || []}
            renderItem={(scan) => (
              <List.Item>
                <List.Item.Meta
                  avatar={getStatusIcon(scan.status)}
                  title={
                    <Space>
                      <Text strong>{scan.name}</Text>
                      <Tag color={getStatusColor(scan.status)}>
                        {scan.status.toUpperCase()}
                      </Tag>
                    </Space>
                  }
                  description={
                    <Space direction="vertical" size="small">
                      <Text type="secondary">
                        Type: {scan.scan_type.toUpperCase()} | 
                        Findings: {scan.total_findings || 0} | 
                        CVEs: {scan.unique_cves || 0}
                      </Text>
                      <Text type="secondary">
                        Started: {new Date(scan.started_at).toLocaleString()}
                        {scan.completed_at && (
                          <> | Completed: {new Date(scan.completed_at).toLocaleString()}</>
                        )}
                      </Text>
                      {scan.error_message && (
                        <Text type="danger">{scan.error_message}</Text>
                      )}
                    </Space>
                  }
                />
              </List.Item>
            )}
            locale={{ emptyText: 'No scans found' }}
          />
        </Card>
      </motion.div>
    </UploadContainer>
  );
};

export default Upload;
