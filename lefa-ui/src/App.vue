<template>
  <div class='app'>
    <router-view></router-view>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue'

export default defineComponent({
  name: 'App',
  components: {
    // HelloWorld
  }
})
</script>

<style>
/* 浏览器初始化，待修改 */
html,
body,
ul,
li,
ol,
dl,
dd,
dt,
p,
h1,
h2,
h3,
h4,
h5,
h6,
form,
fieldset,
legend,
img {
  margin: 0;
  padding: 0;
}
fieldset,
img {
  border: none;
}
img {
  display: block;
}
ul,
ol {
  list-style: none;
}
input {
  padding-top: 0;
  padding-bottom: 0;
  font-family: 'SimSun', '宋体';
}
select,
input,
textarea {
  font-size: 12px;
  margin: 0;
}
textarea {
  resize: none;
}
table {
  border-collapse: collapse;
}
body {
  font-size: 12px;
  color: #333;
}
.clearfix:after {
  content: '.';
  display: block;
  height: 0;
  visibility: hidden;
  clear: both;
}
.clearfix {
  zoom: 1;
}
a {
  color: #333;
  text-decoration: none;
}
a:hover {
  color: #666;
  text-decoration: none;
}
</style>
