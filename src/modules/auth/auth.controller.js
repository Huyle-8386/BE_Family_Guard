const pool = require("../../config/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// REGISTER
exports.register = async (req, res) => {
  try {
    const {
      full_name,
      birthday,
      gender,
      address,
      email,
      phone_number,
      password
    } = req.body;

    // check tồn tại
    const checkUser = await pool.query(
      "SELECT * FROM users WHERE email = $1 OR phone_number = $2",
      [email, phone_number]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ message: "Email hoặc SĐT đã tồn tại" });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // insert user
    const result = await pool.query(
      `INSERT INTO users 
      (full_name, birthday, gender, address, email, phone_number, password)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *`,
      [full_name, birthday, gender, address, email, phone_number, hashedPassword]
    );

    res.json({
      message: "Đăng ký thành công",
      user: result.rows[0]
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


// // LOGIN
// exports.login = async (req, res) => {
//   try {
//     const { identifier, password } = req.body;
//     // identifier = email hoặc phone

//     const userRes = await pool.query(
//       "SELECT * FROM users WHERE email = $1 OR phone_number = $1",
//       [identifier]
//     );

//     if (userRes.rows.length === 0) {
//       return res.status(400).json({ message: "User không tồn tại" });
//     }

//     const user = userRes.rows[0];

//     // check password
//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(400).json({ message: "Sai mật khẩu" });
//     }

//     // tạo token
//     const token = jwt.sign(
//       { id: user.id },
//       process.env.JWT_SECRET,
//       { expiresIn: "7d" }
//     );

//     res.json({
//       message: "Đăng nhập thành công",
//       token,
//       user
//     });

//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// };


// LOGIN
exports.login = async (req, res) => {
  try {
    const { identifier, password } = req.body;

    const userRes = await pool.query(
      "SELECT * FROM users WHERE email = $1 OR phone_number = $1",
      [identifier]
    );

    if (userRes.rows.length === 0) {
      return res.status(400).json({ message: "User không tồn tại" });
    }

    const user = userRes.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Sai mật khẩu" });
    }

    // Access Token (ngắn hạn)
    const accessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    // Refresh Token (dài hạn)
    const refreshToken = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Lưu refresh token vào DB
    await pool.query(
      "UPDATE users SET refresh_token = $1 WHERE id = $2",
      [refreshToken, user.id]
    );

    res.json({
      message: "Đăng nhập thành công",
      accessToken,
      refreshToken
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


// Refresh Token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ message: "Không có refresh token" });
    }

    // kiểm tra DB
    const userRes = await pool.query(
      "SELECT * FROM users WHERE refresh_token = $1",
      [refreshToken]
    );

    if (userRes.rows.length === 0) {
      return res.status(403).json({ message: "Refresh token không hợp lệ" });
    }

    // verify token
    jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: "Token hết hạn hoặc sai" });
      }

      // tạo access token mới
      const newAccessToken = jwt.sign(
        { id: decoded.id },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );

      res.json({
        accessToken: newAccessToken
      });
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};