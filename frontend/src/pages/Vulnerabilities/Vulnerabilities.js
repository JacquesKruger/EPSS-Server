import React, { useState, useEffect } from 'react';
import { 
  Card, 
  Typography, 
  Table, 
  Input, 
  Select, 
  Button, 
  Tag, 
  Space, 
  Row, 
  Col, 
  Statistic,
  message,
  Spin
} from 'antd';
import { SearchOutlined, ReloadOutlined } from '@ant-design/icons';
import { apiService } from '../../services/api';

const { Title } = Typography;
const { Option } = Select;
const { Search } = Input;

const Vulnerabilities = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanInfo, setScanInfo] = useState(null);
  const [filters, setFilters] = useState({
    search: '',
    severity: '',
    status: ''
  });
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0
  });

  // Get scan_id from URL parameters
  const getScanIdFromUrl = () => {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('scan_id');
  };

  const loadScanInfo = async (scanId) => {
    if (!scanId) return;
    
    try {
      const response = await apiService.getDashboardData();
      const scan = response.recent_scans?.find(s => s.scan_id === parseInt(scanId));
      if (scan) {
        setScanInfo(scan);
      }
    } catch (error) {
      console.error('Failed to load scan info:', error);
    }
  };

  const loadVulnerabilities = async (params = {}) => {
    try {
      setLoading(true);
      const scanId = getScanIdFromUrl();
      const requestParams = {
        skip: ((pagination.current || 1) - 1) * (pagination.pageSize || 10),
        limit: pagination.pageSize || 10,
        ...filters,
        ...params
      };
      
      // Add scan_id to request if present in URL
      if (scanId) {
        requestParams.scan_id = scanId;
      }
      
      const response = await apiService.getVulnerabilities(requestParams);
      
      setVulnerabilities(response.vulnerabilities || []);
      setPagination(prev => ({
        ...prev,
        total: response.total || 0
      }));
    } catch (error) {
      console.error('Failed to load vulnerabilities:', error);
      message.error('Failed to load vulnerabilities');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const scanId = getScanIdFromUrl();
    if (scanId) {
      loadScanInfo(scanId);
    }
    loadVulnerabilities();
  }, [pagination.current, pagination.pageSize]);

  // Load scan info when component mounts or scan_id changes
  useEffect(() => {
    const scanId = getScanIdFromUrl();
    if (scanId) {
      loadScanInfo(scanId);
    }
  }, [window.location.search]);

  const handleSearch = (value) => {
    setFilters(prev => ({ ...prev, search: value }));
    setPagination(prev => ({ ...prev, current: 1 }));
    loadVulnerabilities({ search: value });
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, current: 1 }));
    loadVulnerabilities({ [key]: value });
  };

  const handleTableChange = (pagination, filters, sorter) => {
    setPagination(pagination);
    
    // Prepare request parameters
    const requestParams = {
      skip: ((pagination.current || 1) - 1) * (pagination.pageSize || 10),
      limit: pagination.pageSize || 10
    };
    
    // Handle sorting
    if (sorter) {
      const sortField = sorter.field || sorter.columnKey;
      if (sortField && sorter.order) {
        const order = sorter.order === 'ascend' ? 'asc' : 'desc';
        requestParams.sort_by = sortField;
        requestParams.sort_order = order;
      }
    }
    
    // Pass through active filters (e.g., severity)
    if (filters && filters.cvss_severity && filters.cvss_severity.length > 0) {
      requestParams.severity = filters.cvss_severity[0];
    }
    
    // Trigger new API call with updated parameters
    loadVulnerabilities(requestParams);
  };

  const getSeverityColor = (severity) => {
    const severityMap = {
      'critical': 'red',
      'high': 'orange',
      'medium': 'yellow',
      'low': 'green'
    };
    return severityMap[severity?.toLowerCase()] || 'default';
  };

  const columns = [
    {
      title: 'CVE ID',
      dataIndex: 'cve_id',
      key: 'cve_id',
      width: 120,
      sorter: true,
      render: (text) => (
        <a href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${text}`} target="_blank" rel="noopener noreferrer">
          {text}
        </a>
      )
    },
    {
      title: 'Title',
      dataIndex: 'title',
      key: 'title',
      ellipsis: true,
      width: 300
    },
    {
      title: 'CVSS Score',
      dataIndex: 'cvss_score',
      key: 'cvss_score',
      width: 100,
      render: (score) => score ? score.toFixed(1) : 'N/A',
      sorter: true
    },
    {
      title: 'Severity',
      dataIndex: 'cvss_severity',
      key: 'cvss_severity',
      width: 100,
      render: (severity) => (
        <Tag color={getSeverityColor(severity)}>
          {severity?.toUpperCase() || 'UNKNOWN'}
        </Tag>
      ),
      filters: [
        { text: 'Critical', value: 'critical' },
        { text: 'High', value: 'high' },
        { text: 'Medium', value: 'medium' },
        { text: 'Low', value: 'low' }
      ],
      onFilter: (value, record) => record.cvss_severity?.toLowerCase() === value
    },
    {
      title: 'EPSS Score',
      dataIndex: 'epss_score',
      key: 'epss_score',
      width: 100,
      render: (score) => score ? (score * 100).toFixed(2) + '%' : 'N/A',
      sorter: true
    },
    {
      title: 'CPR Score',
      dataIndex: 'cpr_score',
      key: 'cpr_score',
      width: 100,
      render: (score) => score ? score.toFixed(2) : 'N/A',
      sorter: true, // Use server-side sorting
      defaultSortOrder: 'descend' // Default sort by CPR Score descending
    },
    {
      title: 'Findings',
      dataIndex: 'findings_count',
      key: 'findings_count',
      width: 80,
      render: (count) => count || 0
    },
    {
      title: 'Last Updated',
      dataIndex: 'updated_at',
      key: 'updated_at',
      width: 120,
      render: (date) => date ? new Date(date).toLocaleDateString() : 'N/A'
    }
  ];

  const totalVulnerabilities = pagination.total || 0;
  const criticalCount = vulnerabilities.filter(v => v.cvss_severity?.toLowerCase() === 'critical').length;
  const highCount = vulnerabilities.filter(v => v.cvss_severity?.toLowerCase() === 'high').length;

  return (
    <div>
      <Title level={2}>Vulnerability Management</Title>
      
      {/* Scan Reference Section */}
      {scanInfo && (
        <Card style={{ marginBottom: 16, backgroundColor: '#f6ffed', border: '1px solid #b7eb8f' }}>
          <Row gutter={16} align="middle">
            <Col span={18}>
              <div>
                <Title level={4} style={{ margin: 0, color: '#52c41a' }}>
                  📊 Viewing Scan Results: {scanInfo.name}
                </Title>
                <div style={{ marginTop: 8, color: '#666' }}>
                  <Space split="|">
                    <span><strong>Scan ID:</strong> {scanInfo.scan_id}</span>
                    <span><strong>Type:</strong> {scanInfo.scan_type?.toUpperCase()}</span>
                    <span><strong>Status:</strong> {scanInfo.status?.toUpperCase()}</span>
                    <span><strong>Findings:</strong> {scanInfo.total_findings || 0}</span>
                    <span><strong>Unique CVEs:</strong> {scanInfo.unique_cves || 0}</span>
                  </Space>
                </div>
                <div style={{ marginTop: 4, fontSize: '12px', color: '#999' }}>
                  Started: {scanInfo.started_at ? new Date(scanInfo.started_at).toLocaleString() : 'N/A'}
                  {scanInfo.completed_at && (
                    <span> | Completed: {new Date(scanInfo.completed_at).toLocaleString()}</span>
                  )}
                </div>
              </div>
            </Col>
            <Col span={6} style={{ textAlign: 'right' }}>
              <Button 
                type="link" 
                onClick={() => window.location.href = '/vulnerabilities'}
                style={{ color: '#52c41a' }}
              >
                View All Vulnerabilities
              </Button>
            </Col>
          </Row>
        </Card>
      )}
      
      {/* Statistics Cards */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic title="Total Vulnerabilities" value={totalVulnerabilities} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="Critical" value={criticalCount} valueStyle={{ color: '#cf1322' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="High" value={highCount} valueStyle={{ color: '#fa8c16' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="With EPSS" value={vulnerabilities.filter(v => v.epss_score).length} />
          </Card>
        </Col>
      </Row>

      {/* Filters */}
      <Card style={{ marginBottom: 16 }}>
        <Row gutter={16} align="middle">
          <Col span={8}>
            <Search
              placeholder="Search CVE ID or title..."
              onSearch={handleSearch}
              enterButton={<SearchOutlined />}
              allowClear
            />
          </Col>
          <Col span={4}>
            <Select
              placeholder="Severity"
              style={{ width: '100%' }}
              allowClear
              onChange={(value) => handleFilterChange('severity', value)}
            >
              <Option value="critical">Critical</Option>
              <Option value="high">High</Option>
              <Option value="medium">Medium</Option>
              <Option value="low">Low</Option>
            </Select>
          </Col>
          <Col span={4}>
            <Button 
              icon={<ReloadOutlined />} 
              onClick={() => loadVulnerabilities()}
              loading={loading}
            >
              Refresh
            </Button>
          </Col>
        </Row>
      </Card>

      {/* Vulnerabilities Table */}
      <Card>
        <Table
          columns={columns}
          dataSource={vulnerabilities}
          rowKey="id"
          loading={loading}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: pagination.total,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => 
              `${range[0]}-${range[1]} of ${total} vulnerabilities`
          }}
          onChange={handleTableChange}
          scroll={{ x: 1000 }}
        />
      </Card>
    </div>
  );
};

export default Vulnerabilities;
