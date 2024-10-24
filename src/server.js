import app from './app.js';
import { messages } from './constants/constant.js'

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(messages.logMessages.INFO.SERVER_STARTED(PORT));

});
