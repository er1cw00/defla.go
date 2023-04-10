import React, { Component, useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { List, Button, Input } from 'antd';
import VirtualList from 'rc-virtual-list';

class FunctionInfo extends React.Component {

  constructor(props) {
    super(props);
    this.state = {
                    name: '',
                    start: '',
                    end:''
                };
    this.handleSubmit = this.handleSubmit.bind(this);
    this.handleChange = this.handleChange.bind(this);
  }
  handleSubmit(event) {
      alert('A name was submitted: ' + this.state.name);
      event.preventDefault();
  }
  handleChange(event) {
      const name = event.target.name;
      const value = event.target.value;
      console.log('handleChange: ' + name + ', value:' + value)
      if (name == 'start' || name == 'end') {
        console.log('check!')
      }
      this.setState({[name]: value});
  }
  render() {
    return (
      <div> 
        <div></div>
        <div style={{margin:'10px'}}> <label>name: </label><Input style={{width: '180px'}} name="name" value={this.state.name} onChange={this.handleChange}/></div>
        <div style={{margin:'10px'}}> <label>start: </label><Input style={{width: '180px'}}  name="start" value={this.state.start} onChange={this.handleChange}/></div>
        <div style={{margin:'10px'}}> <label>end: </label><Input style={{width: '180px'}}  name="end" value={this.state.end} onChange={this.handleChange}/></div>
        <Button type="primary">Parse</Button>
      </div>
    );
  }
}

const ContainerHeight = 800
class Function extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      data: [
        {name: "func_1", start:"0x111", end:"0x222"},
        {name: "func_2", start:"0x111", end:"0x222"},
        {name: "func_3", start:"0x111", end:"0x222"},
        {name: "func_4", start:"0x111", end:"0x222"},
        {name: "func_5", start:"0x111", end:"0x222"},
        {name: "func_6", start:"0x111", end:"0x222"},
        {name: "func_7", start:"0x111", end:"0x222"},
        {name: "func_8", start:"0x111", end:"0x222"},
        {name: "func_9", start:"0x111", end:"0x222"},
        {name: "func_10", start:"0x111", end:"0x222"},
        {name: "func_1", start:"0x111", end:"0x222"},
        {name: "func_2", start:"0x111", end:"0x222"},
        {name: "func_3", start:"0x111", end:"0x222"},
        {name: "func_4", start:"0x111", end:"0x222"},
        {name: "func_5", start:"0x111", end:"0x222"},
        {name: "func_6", start:"0x111", end:"0x222"},
        {name: "func_7", start:"0x111", end:"0x222"},
        {name: "func_8", start:"0x111", end:"0x222"},
        {name: "func_9", start:"0x111", end:"0x222"},
      ]
    }
    this.appendData = this.appendData.bind(this);
    this.onScroll = this.onScroll.bind(this)
  }
  appendData() {

  }
  onScroll(e) {
    if (e.currentTarget.scrollHeight - e.currentTarget.scrollTop === ContainerHeight) {
      this.appendData();
    }
  };
  render() {
    return (
      <List  header={<FunctionInfo />}>
        <VirtualList
          data={this.state.data}
          height={ContainerHeight}
          itemHeight={32}
          itemKey="name"
          onScroll={this.onScroll}
        >
          {(item) => (
            <List.Item key={item.name}>
              {item.name}
            </List.Item>
          )}
        </VirtualList>
      </List>
    )
  }
}
export default Function;