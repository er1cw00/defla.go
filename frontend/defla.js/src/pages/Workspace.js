import React, { Component } from 'react';
import ReactDOM from 'react-dom/client';
import { Col, Divider, Row } from 'antd';

import Function from './components/Function';
import BBList from './components/BBList';
import BBInfo from './components/BBInfo';
import styles from './pages.css'

class Workspace extends React.Component {

  render() {
    return (
    <div> 
      <Row>
        <Col flex={2}>
          <Function />
        </Col>
        <Col flex={6}>
          <BBInfo />
          <BBList />
        </Col>
      </Row>
    </div>
     
    );
  }
  // render() {
  //   return (
  //       <div className={styles.boxLayout}>
  //       <div className={styles.leftLayout}><Function /> </div>
  //       <div className={styles.rightLayout}>  
  //           <div><BBInfo /></div>
  //           <div><BBList /></div><div/>
  //       </div>
  //       </div>
  //   );
  // }
}
export default Workspace;