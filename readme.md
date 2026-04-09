
#快速打包教程

无需求助ai


系统必须安装nodejs


如果没有可以使用现成版本


项目根目录执行

第一步执行：
npm install


安装依赖

第二步执行：
npm run compile


编译

第三步执行：
npx vsce package --no-dependencies --allow-missing-repository


打包



打包完了后项目根目录会出现一个：wukong-mcp-1.4.0.vsix的文件，拖到cursor的插件市场列表即可安装使用


界面截图

<img width="430" height="842" alt="image" src="https://github.com/user-attachments/assets/493c8fb3-b5cc-43bd-9d3c-464e1c00fde3" />



总结：

npm install

npm run compile

npx vsce package --no-dependencies --allow-missing-repository



到处结束，超级简单


插件里已去除卡密验证界面

感谢支持
