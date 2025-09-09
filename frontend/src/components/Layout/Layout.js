import React, { useState } from 'react';
import { Layout as AntLayout, Menu, Avatar, Dropdown, Space, Typography } from 'antd';
import {
  DashboardOutlined,
  UploadOutlined,
  BugOutlined,
  FileTextOutlined,
  BarChartOutlined,
  UserOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import styled from 'styled-components';

const { Header, Sider, Content } = AntLayout;
const { Text } = Typography;

const StyledLayout = styled(AntLayout)`
  min-height: 100vh;
`;

const StyledHeader = styled(Header)`
  background: ${props => props.theme.colors.surface};
  padding: 0 ${props => props.theme.spacing.lg};
  box-shadow: ${props => props.theme.shadows.sm};
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: ${props => props.theme.zIndex.sticky};
`;

const StyledSider = styled(Sider)`
  background: ${props => props.theme.colors.sidebar};
  
  .ant-layout-sider-trigger {
    background: ${props => props.theme.colors.sidebar};
    color: ${props => props.theme.colors.textInverse};
  }
`;

const StyledContent = styled(Content)`
  margin: ${props => props.theme.spacing.lg};
  padding: ${props => props.theme.spacing.lg};
  background: ${props => props.theme.colors.background};
  border-radius: ${props => props.theme.borderRadius.md};
  min-height: calc(100vh - 112px);
`;

const Logo = styled.div`
  display: flex;
  align-items: center;
  color: ${props => props.theme.colors.textInverse};
  font-size: ${props => props.theme.typography.fontSize.lg};
  font-weight: ${props => props.theme.typography.fontWeight.bold};
  margin-bottom: ${props => props.theme.spacing.lg};
  
  .logo-icon {
    margin-right: ${props => props.theme.spacing.sm};
    font-size: ${props => props.theme.typography.fontSize.xl};
  }
`;

const UserInfo = styled.div`
  display: flex;
  align-items: center;
  color: ${props => props.theme.colors.textInverse};
`;

const menuItems = [
  {
    key: '/dashboard',
    icon: <DashboardOutlined />,
    label: 'Dashboard',
  },
  {
    key: '/upload',
    icon: <UploadOutlined />,
    label: 'Upload CSV',
  },
  {
    key: '/vulnerabilities',
    icon: <BugOutlined />,
    label: 'Vulnerabilities',
  },
  {
    key: '/risk-analysis',
    icon: <BarChartOutlined />,
    label: 'Risk Analysis',
  },
  {
    key: '/reports',
    icon: <FileTextOutlined />,
    label: 'Reports',
  },
];

const Layout = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  const handleMenuClick = ({ key }) => {
    navigate(key);
  };

  const userMenuItems = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: 'Profile',
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: 'Logout',
    },
  ];

  const handleUserMenuClick = ({ key }) => {
    if (key === 'logout') {
      // Handle logout
      console.log('Logout clicked');
    } else if (key === 'profile') {
      // Handle profile
      console.log('Profile clicked');
    }
  };

  return (
    <StyledLayout>
      <StyledSider
        trigger={null}
        collapsible
        collapsed={collapsed}
        width={250}
        collapsedWidth={80}
      >
        <Logo>
          <span className="logo-icon">🛡️</span>
          {!collapsed && 'CPR Score'}
        </Logo>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={handleMenuClick}
        />
      </StyledSider>
      
      <AntLayout>
        <StyledHeader>
          <Space>
            {React.createElement(collapsed ? MenuUnfoldOutlined : MenuFoldOutlined, {
              style: { fontSize: '18px', cursor: 'pointer' },
              onClick: () => setCollapsed(!collapsed),
            })}
            <Text strong style={{ fontSize: '18px' }}>
              CPR Score Server
            </Text>
          </Space>
          
          <UserInfo>
            <Dropdown
              menu={{
                items: userMenuItems,
                onClick: handleUserMenuClick,
              }}
              placement="bottomRight"
            >
              <Space style={{ cursor: 'pointer' }}>
                <Avatar icon={<UserOutlined />} />
                <Text style={{ color: '#fff' }}>Admin User</Text>
              </Space>
            </Dropdown>
          </UserInfo>
        </StyledHeader>
        
        <StyledContent>
          {children}
        </StyledContent>
      </AntLayout>
    </StyledLayout>
  );
};

export default Layout;
