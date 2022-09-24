const express = require("express");
const {
  deleteBlog,
  updateBlog,
  createBlog,
  getAllBlogs,
  getBlog,
} = require("../controllers/blog-controllers");
const { protect } = require("../controllers/user-controllers");

const router = express.Router();

router
  .route("/:id")
  .delete(protect, deleteBlog)
  .patch(protect, updateBlog)
  .get(protect, getBlog);
router.post("/:authorId?", protect, createBlog);
router.get("/", getAllBlogs);

module.exports = router;
