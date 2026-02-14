import React from 'react';
import { Typography } from 'antd';

const { Text } = Typography;

const RecentScans = ({ data }) => {
  return (
    <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Text type="secondary">Recent scans coming soon...</Text>
    </div>
  );
};

export default RecentScans;

