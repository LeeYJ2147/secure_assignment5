const HibernateUtil = require('HibernateUtil');
const session = HibernateUtil.getSessionFactory().openSession();
const userInput = "admin";
const query = session.createQuery("FROM User WHERE username = :username");
query.setParameter("username", userInput);
const result = query.list();
console.log(result);