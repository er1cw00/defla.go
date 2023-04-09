import React, { Component } from 'react';
import ReactDOM from 'react-dom/client';
import { Graphviz } from 'graphviz-react';


class BBList extends React.Component {
    render() {
        const dot = 'graph{a--b}';
        return (
            <Graphviz dot={dot} />
        );
    }
}

export default BBList;