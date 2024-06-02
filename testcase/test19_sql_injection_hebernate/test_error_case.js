const HibernateUtil = require('HibernateUtil');
const session = HibernateUtil.getSessionFactory().openSession();
const userInput = "admin' OR '1'='1";
const query = session.createQuery("FROM User WHERE username = '" + userInput + "'");
const result = query.list();
console.log(result);