const express = require("express");
const {
  deleteBlog,
  updateBlog,
  createBlog,
  getAllBlogs,
  getBlog,
} = require("../controllers/blog-controllers");
const { protect, restrictTo } = require("../controllers/user-controllers");

const router = express.Router();

router
  .route("/:id")
  .delete(protect, restrictTo("blogger", "admin"), deleteBlog)
  .patch(protect, restrictTo("blogger"), updateBlog)
  .get(protect, getBlog);
router.post("/:authorId?", protect, restrictTo("blogger"), createBlog);
router.get("/", getAllBlogs);

module.exports = router;
