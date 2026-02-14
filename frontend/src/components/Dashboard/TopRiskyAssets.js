import React from 'react';
import { Typography } from 'antd';

const { Text } = Typography;

const TopRiskyAssets = ({ data }) => {
  return (
    <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Text type="secondary">Top risky assets coming soon...</Text>
    </div>
  );
};

export default TopRiskyAssets;

