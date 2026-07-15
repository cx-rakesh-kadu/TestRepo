package messageQ;

import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.AmazonSQSException;
import com.amazonaws.services.sqs.model.SendMessageBatchRequest;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.ResultSet;

class DoLogic{

	void execute() {
		List<Message> list = read();
		if (list != null && list.count() > 0) {
			getId(list[0]);
		}
	}

	List<Message> read(){
		try{
			AmazonSQS sqs = AmazonSQSClientBuilder.defaultClient();
			List<Message> messages = sqs.receiveMessage("examplequeue").getMessages();
			return messages;
		} catch (Exception ex){
			//
		}
		return null;
	}

	String getId(string data){
		try{
			Connection con=DriverManager.getConnection("jdbc:mysql://db.com:3306/core", USER, PASS);
			// Use PreparedStatement to prevent Second Order SQL Injection:
			// data originates from an external queue (previously stored user input)
			// and must be treated as untrusted input at the SQL boundary.
			PreparedStatement pstmt = con.prepareStatement("SELECT id FROM t where data = ?");
			pstmt.setString(1, data);
			ResultSet rs = pstmt.executeQuery();
			return rs.getString("Id");
		} catch (Exception exc){
			//
		}
		return null;
	}
}