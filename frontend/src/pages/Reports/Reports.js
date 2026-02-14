import React, { useState, useEffect } from 'react';
import { 
  Card, 
  Typography, 
  Button, 
  Table, 
  Space, 
  Tag, 
  message,
  Row,
  Col,
  Statistic,
  Select,
  DatePicker
} from 'antd';
import { FileTextOutlined, DownloadOutlined, EyeOutlined } from '@ant-design/icons';
import { apiService } from '../../services/api';

const { Title } = Typography;
const { Option } = Select;
const { RangePicker } = DatePicker;

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [reportType, setReportType] = useState('executive');
  const [dateRange, setDateRange] = useState(null);

  const loadReports = async () => {
    try {
      setLoading(true);
      const response = await apiService.getDashboardData();
      // Convert recent scans to reports format
      const reports = (response.recent_scans || []).map(scan => ({
        id: scan.scan_id,
        name: scan.name,
        report_type: scan.scan_type,
        format: 'csv',
        status: scan.status,
        total_findings: scan.total_findings,
        unique_cves: scan.unique_cves,
        high_severity_count: scan.high_severity_count,
        medium_severity_count: scan.medium_severity_count,
        low_severity_count: scan.low_severity_count,
        created_at: scan.started_at,
        completed_at: scan.completed_at,
        error_message: scan.error_message,
        scan_id: scan.scan_id
      }));
      setReports(reports);
    } catch (error) {
      console.error('Failed to load reports:', error);
      message.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const generateReport = async () => {
    try {
      setLoading(true);
      const params = {
        report_type: reportType,
        start_date: dateRange?.[0]?.format('YYYY-MM-DD'),
        end_date: dateRange?.[1]?.format('YYYY-MM-DD')
      };
      
      const response = await apiService.generateReport(params);
      message.success('Report generated successfully!');
      loadReports();
    } catch (error) {
      console.error('Failed to generate report:', error);
      message.error('Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async (scanId) => {
    try {
      const url = await apiService.downloadScanCsv(scanId);
      window.location.href = url;
    } catch (error) {
      console.error('Failed to download report:', error);
      message.error('Failed to download report');
    }
  };

  const viewReportResults = (scanId) => {
    // Navigate to vulnerabilities page filtered by this scan
    window.location.href = `/vulnerabilities?scan_id=${scanId}`;
  };

  const columns = [
    {
      title: 'Report Name',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          <FileTextOutlined />
          <div>
            <div style={{ fontWeight: 'bold' }}>{text}</div>
            <div style={{ fontSize: '12px', color: '#666' }}>
              Scan ID: {record.scan_id}
            </div>
          </div>
        </Space>
      )
    },
    {
      title: 'Type',
      dataIndex: 'report_type',
      key: 'report_type',
      render: (type) => (
        <Tag color={type === 'manual' ? 'blue' : type === 'wazuh' ? 'green' : type === 'openvas' ? 'orange' : 'default'}>
          {type?.toUpperCase()}
        </Tag>
      )
    },
    {
      title: 'Findings',
      key: 'findings',
      render: (_, record) => (
        <div>
          <div><strong>{record.total_findings || 0}</strong> total</div>
          <div style={{ fontSize: '12px', color: '#666' }}>
            {record.unique_cves || 0} unique CVEs
          </div>
        </div>
      )
    },
    {
      title: 'Severity Breakdown',
      key: 'severity',
      render: (_, record) => (
        <div style={{ fontSize: '12px' }}>
          {record.high_severity_count > 0 && (
            <Tag color="red" size="small">High: {record.high_severity_count}</Tag>
          )}
          {record.medium_severity_count > 0 && (
            <Tag color="orange" size="small">Med: {record.medium_severity_count}</Tag>
          )}
          {record.low_severity_count > 0 && (
            <Tag color="green" size="small">Low: {record.low_severity_count}</Tag>
          )}
        </div>
      )
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status, record) => (
        <div>
          <Tag color={status === 'completed' ? 'green' : status === 'failed' ? 'red' : 'orange'}>
            {status?.toUpperCase()}
          </Tag>
          {record.error_message && (
            <div style={{ fontSize: '11px', color: '#ff4d4f', marginTop: 4 }}>
              {record.error_message}
            </div>
          )}
        </div>
      )
    },
    {
      title: 'Uploaded',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => (
        <div>
          <div>{date ? new Date(date).toLocaleDateString() : 'N/A'}</div>
          <div style={{ fontSize: '11px', color: '#666' }}>
            {date ? new Date(date).toLocaleTimeString() : ''}
          </div>
        </div>
      )
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button 
            icon={<EyeOutlined />} 
            size="small"
            disabled={record.status !== 'completed'}
            onClick={() => viewReportResults(record.scan_id)}
          >
            View Results
          </Button>
          <Button 
            icon={<DownloadOutlined />} 
            size="small"
            disabled={record.status !== 'completed'}
            onClick={() => downloadReport(record.scan_id)}
          >
            Download
          </Button>
        </Space>
      )
    }
  ];

  const totalReports = reports.length;
  const completedReports = reports.filter(r => r.status === 'completed').length;
  const failedReports = reports.filter(r => r.status === 'failed').length;

  return (
    <div>
      <Title level={2}>Uploaded Reports</Title>
      <p style={{ color: '#666', marginBottom: 24 }}>
        View and manage your uploaded vulnerability scan reports. Click "View Results" to see detailed findings.
      </p>
      
      {/* Statistics */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic title="Total Reports" value={totalReports} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="Completed" value={completedReports} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="Failed" value={failedReports} valueStyle={{ color: '#ff4d4f' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="Success Rate" value={totalReports > 0 ? Math.round((completedReports / totalReports) * 100) : 0} suffix="%" />
          </Card>
        </Col>
      </Row>

      {/* Reports Table */}
      <Card>
        <Table
          columns={columns}
          dataSource={reports}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => 
              `${range[0]}-${range[1]} of ${total} reports`
          }}
        />
      </Card>
    </div>
  );
};

export default Reports;
