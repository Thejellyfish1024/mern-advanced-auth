import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
	const token = req?.cookies?.token;
	// console.log(token);
	
	if (!token) {
		return res.status(401).json({ success: false, message: "Unauthorized - no token provided" });
	}

	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);
		// console.log(decoded);

		// decoded will not be falsy if jwt.verify succeeds, so no need to check !decoded here
		req.userId = decoded.userId;
		next();
	} catch (error) {
		// console.log("Error in verifyToken: ", error.message);
		if (error.name === "JsonWebTokenError") {
			return res.status(401).json({ success: false, message: "Unauthorized - invalid token" });
		} else if (error.name === "TokenExpiredError") {
			return res.status(401).json({ success: false, message: "Unauthorized - token expired" });
		} else {
			return res.status(500).json({ success: false, message: "Server error" });
		}
	}
};
