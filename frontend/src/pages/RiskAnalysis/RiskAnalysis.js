import React, { useState, useEffect } from 'react';
import { 
  Card, 
  Typography, 
  Table, 
  Row, 
  Col, 
  Statistic, 
  Progress, 
  Tag, 
  Space,
  Select,
  Button,
  message
} from 'antd';
import { 
  ExclamationCircleOutlined, 
  WarningOutlined, 
  InfoCircleOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import { apiService } from '../../services/api';

const { Title } = Typography;
const { Option } = Select;

const RiskAnalysis = () => {
  const [riskData, setRiskData] = useState({});
  const [loading, setLoading] = useState(false);
  const [riskLevel, setRiskLevel] = useState('all');

  const loadRiskAnalysis = async () => {
    try {
      setLoading(true);
      const response = await apiService.getRiskAnalysis({ risk_level: riskLevel });
      setRiskData(response);
    } catch (error) {
      console.error('Failed to load risk analysis:', error);
      message.error('Failed to load risk analysis data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRiskAnalysis();
  }, [riskLevel]);

  const getRiskColor = (level) => {
    const colors = {
      'critical': '#ff4d4f',
      'high': '#fa8c16',
      'medium': '#faad14',
      'low': '#52c41a'
    };
    return colors[level] || '#d9d9d9';
  };

  const getRiskIcon = (level) => {
    const icons = {
      'critical': <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />,
      'high': <WarningOutlined style={{ color: '#fa8c16' }} />,
      'medium': <InfoCircleOutlined style={{ color: '#faad14' }} />,
      'low': <InfoCircleOutlined style={{ color: '#52c41a' }} />
    };
    return icons[level] || <InfoCircleOutlined />;
  };

  const columns = [
    {
      title: 'CVE ID',
      dataIndex: 'cve_id',
      key: 'cve_id',
      width: 120,
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
      title: 'Risk Level',
      dataIndex: 'cpr_risk_level',
      key: 'cpr_risk_level',
      width: 100,
      render: (level) => (
        <Space>
          {getRiskIcon(level)}
          <Tag color={getRiskColor(level)}>
            {level?.toUpperCase() || 'UNKNOWN'}
          </Tag>
        </Space>
      ),
      sorter: (a, b) => {
        const order = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
        return (order[b.cpr_risk_level] || 0) - (order[a.cpr_risk_level] || 0);
      }
    },
    {
      title: 'CPR Score',
      dataIndex: 'cpr_score',
      key: 'cpr_score',
      width: 100,
      render: (score) => (
        <Progress 
          percent={score || 0} 
          size="small" 
          strokeColor={getRiskColor(score > 75 ? 'critical' : score > 50 ? 'high' : score > 25 ? 'medium' : 'low')}
        />
      ),
      sorter: (a, b) => (a.cpr_score || 0) - (b.cpr_score || 0)
    },
    {
      title: 'CVSS Score',
      dataIndex: 'cvss_score',
      key: 'cvss_score',
      width: 100,
      render: (score) => score ? score.toFixed(1) : 'N/A'
    },
    {
      title: 'EPSS Score',
      dataIndex: 'epss_score',
      key: 'epss_score',
      width: 100,
      render: (score) => score ? (score * 100).toFixed(2) + '%' : 'N/A'
    },
    {
      title: 'Affected Assets',
      dataIndex: 'affected_assets',
      key: 'affected_assets',
      width: 100,
      render: (count) => count || 0
    }
  ];

  const riskDistribution = riskData.risk_distribution || {};
  const totalVulnerabilities = riskData.total_vulnerabilities || 0;
  const averageCprScore = riskData.average_cpr_score || 0;

  return (
    <div>
      <Title level={2}>Risk Analysis & Prioritization</Title>
      
      {/* Risk Overview */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic 
              title="Total Vulnerabilities" 
              value={totalVulnerabilities}
              prefix={<ExclamationCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic 
              title="Average CPR Score" 
              value={averageCprScore.toFixed(1)}
              suffix="/100"
              valueStyle={{ color: getRiskColor(averageCprScore > 75 ? 'critical' : averageCprScore > 50 ? 'high' : averageCprScore > 25 ? 'medium' : 'low') }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic 
              title="Critical Risks" 
              value={riskDistribution.critical || 0}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic 
              title="High Risks" 
              value={riskDistribution.high || 0}
              valueStyle={{ color: '#fa8c16' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Risk Distribution */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card title="Risk Level Distribution">
            <Row gutter={16}>
              <Col span={12}>
                <div style={{ textAlign: 'center', marginBottom: 16 }}>
                  <div style={{ fontSize: 24, fontWeight: 'bold', color: '#ff4d4f' }}>
                    {riskDistribution.critical || 0}
                  </div>
                  <div>Critical</div>
                </div>
              </Col>
              <Col span={12}>
                <div style={{ textAlign: 'center', marginBottom: 16 }}>
                  <div style={{ fontSize: 24, fontWeight: 'bold', color: '#fa8c16' }}>
                    {riskDistribution.high || 0}
                  </div>
                  <div>High</div>
                </div>
              </Col>
              <Col span={12}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 24, fontWeight: 'bold', color: '#faad14' }}>
                    {riskDistribution.medium || 0}
                  </div>
                  <div>Medium</div>
                </div>
              </Col>
              <Col span={12}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 24, fontWeight: 'bold', color: '#52c41a' }}>
                    {riskDistribution.low || 0}
                  </div>
                  <div>Low</div>
                </div>
              </Col>
            </Row>
          </Card>
        </Col>
        <Col span={12}>
          <Card title="Risk Analysis Controls">
            <Space direction="vertical" style={{ width: '100%' }}>
              <div>
                <label>Filter by Risk Level:</label>
                <Select
                  value={riskLevel}
                  onChange={setRiskLevel}
                  style={{ width: '100%', marginTop: 8 }}
                >
                  <Option value="all">All Risk Levels</Option>
                  <Option value="critical">Critical Only</Option>
                  <Option value="high">High and Above</Option>
                  <Option value="medium">Medium and Above</Option>
                  <Option value="low">Low and Above</Option>
                </Select>
              </div>
              <Button 
                icon={<ReloadOutlined />} 
                onClick={loadRiskAnalysis}
                loading={loading}
              >
                Refresh Analysis
              </Button>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* Risk Analysis Table */}
      <Card>
        <Table
          columns={columns}
          dataSource={riskData.vulnerabilities || []}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => 
              `${range[0]}-${range[1]} of ${total} vulnerabilities`
          }}
          scroll={{ x: 1000 }}
        />
      </Card>
    </div>
  );
};

export default RiskAnalysis;
