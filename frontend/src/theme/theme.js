export const theme = {
  colors: {
    // Primary colors
    primary: '#1890ff',
    primaryHover: '#40a9ff',
    primaryActive: '#096dd9',
    
    // Secondary colors
    secondary: '#722ed1',
    secondaryHover: '#9254de',
    
    // Status colors
    success: '#52c41a',
    warning: '#faad14',
    error: '#ff4d4f',
    info: '#1890ff',
    
    // Risk level colors
    critical: '#ff4d4f',
    high: '#ff7a45',
    medium: '#faad14',
    low: '#52c41a',
    
    // Background colors
    background: '#f5f5f5',
    surface: '#ffffff',
    sidebar: '#001529',
    card: '#ffffff',
    
    // Text colors
    text: '#262626',
    textSecondary: '#8c8c8c',
    textLight: '#bfbfbf',
    textInverse: '#ffffff',
    
    // Border colors
    border: '#d9d9d9',
    borderLight: '#f0f0f0',
    
    // Chart colors
    chart1: '#1890ff',
    chart2: '#52c41a',
    chart3: '#faad14',
    chart4: '#ff4d4f',
    chart5: '#722ed1',
    chart6: '#13c2c2',
    chart7: '#eb2f96',
    chart8: '#fa8c16',
  },
  
  spacing: {
    xs: '4px',
    sm: '8px',
    md: '16px',
    lg: '24px',
    xl: '32px',
    xxl: '48px',
  },
  
  borderRadius: {
    sm: '4px',
    md: '8px',
    lg: '12px',
    xl: '16px',
  },
  
  shadows: {
    sm: '0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24)',
    md: '0 3px 6px rgba(0, 0, 0, 0.16), 0 3px 6px rgba(0, 0, 0, 0.23)',
    lg: '0 10px 20px rgba(0, 0, 0, 0.19), 0 6px 6px rgba(0, 0, 0, 0.23)',
    xl: '0 14px 28px rgba(0, 0, 0, 0.25), 0 10px 10px rgba(0, 0, 0, 0.22)',
  },
  
  breakpoints: {
    xs: '480px',
    sm: '576px',
    md: '768px',
    lg: '992px',
    xl: '1200px',
    xxl: '1600px',
  },
  
  typography: {
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    fontSize: {
      xs: '12px',
      sm: '14px',
      md: '16px',
      lg: '18px',
      xl: '20px',
      xxl: '24px',
      xxxl: '32px',
    },
    fontWeight: {
      light: 300,
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
    },
    lineHeight: {
      tight: 1.2,
      normal: 1.5,
      relaxed: 1.75,
    },
  },
  
  zIndex: {
    dropdown: 1000,
    sticky: 1020,
    fixed: 1030,
    modal: 1040,
    popover: 1050,
    tooltip: 1060,
  },
};
