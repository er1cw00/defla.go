import React, { Component } from 'react';
import ReactDOM from 'react-dom/client';
import { Graphviz } from 'graphviz-react';

class BBInfo extends React.Component {
    render() {
        return (
          <div>dfadf</div>
        );
    }
}


class BBList extends React.Component {
    render() {
        const dot = `digraph  {
            bgcolor="transparent";
            n1[fontname="arial",label="0x3cfb8",nojustify="true",shape="box",style="filled"];
            n2[fontname="arial",label="0x3d040",nojustify="true",shape="box",style="filled"];
            n3[fontname="arial",label="0x3d088",nojustify="true",shape="box",style="filled"];
            n4[fontname="arial",label="0x3d090",nojustify="true",shape="box",style="filled"];
            n5[fontname="arial",label="0x3d098",nojustify="true",shape="box",style="filled"];
            n6[fontname="arial",label="0x3d0a0",nojustify="true",shape="box",style="filled"];
            n7[fontname="arial",label="0x3d0b0",nojustify="true",shape="box",style="filled"];
            n8[fontname="arial",label="0x3d0c0",nojustify="true",shape="box",style="filled"];
            n9[fontname="arial",label="0x3d0d0",nojustify="true",shape="box",style="filled"];
            n10[fontname="arial",label="0x3d0e0",nojustify="true",shape="box",style="filled"];
            n11[fontname="arial",label="0x3d0e8",nojustify="true",shape="box",style="filled"];
            n12[fontname="arial",label="0x3d0f0",nojustify="true",shape="box",style="filled"];
            n13[fontname="arial",label="0x3d0f8",nojustify="true",shape="box",style="filled"];
            n14[fontname="arial",label="0x3d108",nojustify="true",shape="box",style="filled"];
            n15[fontname="arial",label="0x3d118",nojustify="true",shape="box",style="filled"];
            n16[fontname="arial",label="0x3d134",nojustify="true",shape="box",style="filled"];
            n17[fontname="arial",label="0x3d13c",nojustify="true",shape="box",style="filled"];
            n18[fontname="arial",label="0x3d14c",nojustify="true",shape="box",style="filled"];
            n19[fontname="arial",label="0x3d15c",nojustify="true",shape="box",style="filled"];
            n20[fontname="arial",label="0x3d16c",nojustify="true",shape="box",style="filled"];
            n21[fontname="arial",label="0x3d194",nojustify="true",shape="box",style="filled"];
            n22[fontname="arial",label="0x3d19c",nojustify="true",shape="box",style="filled"];
            n23[fontname="arial",label="0x3d1a4",nojustify="true",shape="box",style="filled"];
            n24[fontname="arial",label="0x3d1b4",nojustify="true",shape="box",style="filled"];
            n25[fontname="arial",label="0x3d1c4",nojustify="true",shape="box",style="filled"];
            n26[fontname="arial",label="0x3d1e0",nojustify="true",shape="box",style="filled"];
            n27[fontname="arial",label="0x3d1f0",nojustify="true",shape="box",style="filled"];
            n28[fontname="arial",label="0x3d200",nojustify="true",shape="box",style="filled"];
            n29[fontname="arial",label="0x3d210",nojustify="true",shape="box",style="filled"];
            n30[fontname="arial",label="0x3d214",nojustify="true",shape="box",style="filled"];
            n31[fontname="arial",label="0x3d224",nojustify="true",shape="box",style="filled"];
            n32[fontname="arial",label="0x3d234",nojustify="true",shape="box",style="filled"];
            n33[fontname="arial",label="0x3d254",nojustify="true",shape="box",style="filled"];
            n34[fontname="arial",label="0x3d264",nojustify="true",shape="box",style="filled"];
            n35[fontname="arial",label="0x3d274",nojustify="true",shape="box",style="filled"];
            n36[fontname="arial",label="0x3d284",nojustify="true",shape="box",style="filled"];
            n37[fontname="arial",label="0x3d294",nojustify="true",shape="box",style="filled"];
            n38[fontname="arial",label="0x3d2a4",nojustify="true",shape="box",style="filled"];
            n39[fontname="arial",label="0x3d2c0",nojustify="true",shape="box",style="filled"];
            n40[fontname="arial",label="0x3d2e0",nojustify="true",shape="box",style="filled"];
            n41[fontname="arial",label="0x3d2fc",nojustify="true",shape="box",style="filled"];
            n42[fontname="arial",label="0x3d30c",nojustify="true",shape="box",style="filled"];
            n43[fontname="arial",label="0x3d31c",nojustify="true",shape="box",style="filled"];
            n44[fontname="arial",label="0x3d334",nojustify="true",shape="box",style="filled"];
            n45[fontname="arial",label="0x3d358",nojustify="true",shape="box",style="filled"];
            n46[fontname="arial",label="0x3d368",nojustify="true",shape="box",style="filled"];
            n47[fontname="arial",label="0x3d3b4",nojustify="true",shape="box",style="filled"];
            n48[fontname="arial",label="0x3d3cc",nojustify="true",shape="box",style="filled"];
            n49[fontname="arial",label="0x3d3dc",nojustify="true",shape="box",style="filled"];
            n50[fontname="arial",label="0x3d3fc",nojustify="true",shape="box",style="filled"];
            n51[fontname="arial",label="0x3d41c",nojustify="true",shape="box",style="filled"];
            n52[fontname="arial",label="0x3d434",nojustify="true",shape="box",style="filled"];
            n53[fontname="arial",label="0x3d454",nojustify="true",shape="box",style="filled"];
            n1->n2;
            n2->n3;
            n3->n4;
            n4->n5;
            n5->n6;
            n6->n7;
            n7->n8;
            n8->n9;
            n9->n10;
            n10->n11;
            n11->n12;
            n12->n13;
            n13->n14;
            n14->n15;
            n15->n16;
            n16->n17;
            n17->n18;
            n18->n19;
            n19->n20;
            n20->n21;
            n21->n22;
            n22->n23;
            n23->n24;
            n24->n25;
            n25->n26;
            n26->n27;
            n27->n28;
            n28->n29;
            n29->n30;
            n30->n31;
            n31->n32;
            n32->n33;
            n33->n34;
            n34->n35;
            n35->n36;
            n36->n37;
            n37->n38;
            n38->n39;
            n39->n40;
            n40->n41;
            n41->n42;
            n42->n43;
            n43->n44;
            n44->n45;
            n45->n46;
            n46->n47;
            n47->n48;
            n48->n49;
            n49->n50;
            n50->n51;
            n51->n52;
            n52->n53;
            
        }`;
        return (
          <div style={{height:'100%', background:'#414141'}  }>
            <BBInfo />
            <Graphviz dot={dot} options={{scale: 1,fit: true}}/>
          </div>
        );
    }
}

export default BBList;