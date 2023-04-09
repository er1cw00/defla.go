import React, { Component } from 'react';
import ReactDOM from 'react-dom/client';
import { Form, List, Typography, Button, Input, Space } from 'antd';


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

class Function extends React.Component {

  constructor(props) {
    super(props);
    this.data = 
            [
              "func_1", 
              "func_2", 
              "func_3", 
              "func_4", 
              "func_5", 
              "func_6", 
              "func_7", 
              "func_8", 
              "func_9", 
              "func_10"
            ]
    
  }

  render() {
    return (
        <List style={{width:'300px'}}
          header={<FunctionInfo />}
          bordered
          dataSource={this.data}
          renderItem={(item) => (
            <List.Item>
              {item}
            </List.Item>
          )}
        />

    );
  }
}
export default Function;