import React from 'react';
import { Row, Col, Card, Statistic, Typography, Spin } from 'antd';
import {
  BugOutlined,
  AlertOutlined,
  SafetyOutlined,
  BarChartOutlined,
  TrendingUpOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import { useQuery } from 'react-query';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import VulnerabilityChart from '../../components/Charts/VulnerabilityChart';
import RiskDistributionChart from '../../components/Charts/RiskDistributionChart';
import RecentScans from '../../components/Dashboard/RecentScans';
import TopRiskyAssets from '../../components/Dashboard/TopRiskyAssets';
import { apiService } from '../../services/api';

const { Title } = Typography;

const DashboardContainer = styled.div`
  .dashboard-header {
    margin-bottom: ${props => props.theme.spacing.xl};
  }

  .stat-card {
    .ant-card-body {
      padding: ${props => props.theme.spacing.lg};
    }
  }

  .chart-card {
    margin-bottom: ${props => props.theme.spacing.lg};
  }
`;

const StatCard = styled(Card)`
  .ant-statistic-title {
    color: ${props => props.theme.colors.textSecondary};
    font-size: ${props => props.theme.typography.fontSize.sm};
  }

  .ant-statistic-content {
    color: ${props => props.theme.colors.text};
  }

  .stat-icon {
    font-size: 24px;
    margin-bottom: ${props => props.theme.spacing.sm};
  }

  &.critical .stat-icon {
    color: ${props => props.theme.colors.critical};
  }

  &.high .stat-icon {
    color: ${props => props.theme.colors.high};
  }

  &.medium .stat-icon {
    color: ${props => props.theme.colors.medium};
  }

  &.low .stat-icon {
    color: ${props => props.theme.colors.low};
  }
`;

const Dashboard = () => {
  const { data: dashboardData, isLoading, error } = useQuery(
    'dashboard',
    apiService.getDashboardData,
    {
      refetchInterval: 30000, // Refetch every 30 seconds
    }
  );

  if (isLoading) {
    return (
      <div style={{ textAlign: 'center', padding: '50px' }}>
        <Spin size="large" />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ textAlign: 'center', padding: '50px' }}>
        <Title level={3} type="danger">
          Failed to load dashboard data
        </Title>
      </div>
    );
  }

  const stats = dashboardData?.statistics || {};
  const riskAnalysis = dashboardData?.risk_analysis || {};

  return (
    <DashboardContainer>
      <div className="dashboard-header">
        <Title level={2}>Security Dashboard</Title>
        <Typography.Text type="secondary">
          Overview of your vulnerability landscape and risk posture
        </Typography.Text>
      </div>

      {/* Statistics Cards */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <StatCard className="stat-card critical">
              <Statistic
                title="Critical Vulnerabilities"
                value={stats.critical_vulnerabilities || 0}
                prefix={<AlertOutlined className="stat-icon" />}
                valueStyle={{ color: '#ff4d4f' }}
              />
            </StatCard>
          </motion.div>
        </Col>
        
        <Col xs={24} sm={12} lg={6}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <StatCard className="stat-card high">
              <Statistic
                title="High Risk Assets"
                value={riskAnalysis.assets_by_risk?.high || 0}
                prefix={<SafetyOutlined className="stat-icon" />}
                valueStyle={{ color: '#ff7a45' }}
              />
            </StatCard>
          </motion.div>
        </Col>
        
        <Col xs={24} sm={12} lg={6}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <StatCard className="stat-card medium">
              <Statistic
                title="Total Vulnerabilities"
                value={stats.total_vulnerabilities || 0}
                prefix={<BugOutlined className="stat-icon" />}
                valueStyle={{ color: '#faad14' }}
              />
            </StatCard>
          </motion.div>
        </Col>
        
        <Col xs={24} sm={12} lg={6}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
          >
            <StatCard className="stat-card low">
              <Statistic
                title="Assets Monitored"
                value={riskAnalysis.total_assets || 0}
                prefix={<BarChartOutlined className="stat-icon" />}
                valueStyle={{ color: '#52c41a' }}
              />
            </StatCard>
          </motion.div>
        </Col>
      </Row>

      {/* Charts Row */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} lg={12}>
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.5 }}
          >
            <Card title="Vulnerability Trends" className="chart-card">
              <VulnerabilityChart data={dashboardData?.vulnerability_trends} />
            </Card>
          </motion.div>
        </Col>
        
        <Col xs={24} lg={12}>
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.6 }}
          >
            <Card title="Risk Distribution" className="chart-card">
              <RiskDistributionChart data={riskAnalysis.assets_by_risk} />
            </Card>
          </motion.div>
        </Col>
      </Row>

      {/* Bottom Row */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7 }}
          >
            <Card title="Recent Scans" className="chart-card">
              <RecentScans data={dashboardData?.recent_scans} />
            </Card>
          </motion.div>
        </Col>
        
        <Col xs={24} lg={12}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.8 }}
          >
            <Card title="Top Risky Assets" className="chart-card">
              <TopRiskyAssets data={riskAnalysis.top_risky_assets} />
            </Card>
          </motion.div>
        </Col>
      </Row>
    </DashboardContainer>
  );
};

export default Dashboard;
