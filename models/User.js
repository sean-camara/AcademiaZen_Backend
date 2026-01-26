const mongoose = require('mongoose');

const TaskSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, default: '' },
  dueDate: { type: String, default: '' },
  completed: { type: Boolean, default: false },
  subjectId: { type: String, default: '' },
  notes: { type: String, default: '' },
  pdfAttachment: {
    name: { type: String, default: '' },
    data: { type: String, default: '' },
  },
}, { _id: false });

const SubjectSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, default: '' },
  color: { type: String, default: '' },
}, { _id: false });

const FlashcardSchema = new mongoose.Schema({
  id: { type: String, required: true },
  subjectId: { type: String, default: '' },
  front: { type: String, default: '' },
  back: { type: String, default: '' },
  box: { type: Number, default: 0 },
  nextReviewDate: { type: String, default: '' },
}, { _id: false });

const FolderItemSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, default: '' },
  type: { type: String, enum: ['note', 'pdf'], default: 'note' },
  content: { type: String, default: '' },
}, { _id: false });

const FolderSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, default: '' },
  parentId: { type: String, default: '' },
  items: { type: [FolderItemSchema], default: [] },
}, { _id: false });

const UserProfileSchema = new mongoose.Schema({
  name: { type: String, default: 'Student' },
  university: { type: String, default: '' },
  semester: { type: String, default: '' },
  quoteEnabled: { type: Boolean, default: true },
}, { _id: false });

const AppSettingsSchema = new mongoose.Schema({
  focusDuration: { type: Number, default: 25 },
  autoBreak: { type: Boolean, default: false },
  ambience: { type: String, default: 'silent' },
  notifications: { type: Boolean, default: true },
  deadlineAlerts: { type: Boolean, default: true },
  dailyBriefing: { type: Boolean, default: true },
  studyReminders: { type: Boolean, default: true },
}, { _id: false });

const ZenStateSchema = new mongoose.Schema({
  tasks: { type: [TaskSchema], default: [] },
  subjects: { type: [SubjectSchema], default: [] },
  flashcards: { type: [FlashcardSchema], default: [] },
  folders: { type: [FolderSchema], default: [] },
  profile: { type: UserProfileSchema, default: () => ({}) },
  settings: { type: AppSettingsSchema, default: () => ({}) },
}, { _id: false });

const UserSchema = new mongoose.Schema({
  uid: { type: String, required: true, unique: true, index: true },
  email: { type: String, default: '' },
  state: { type: ZenStateSchema, default: () => getDefaultState() },
}, { timestamps: true });

function getDefaultState() {
  return {
    tasks: [],
    subjects: [],
    flashcards: [],
    folders: [
      { id: 'general', name: 'General', items: [] },
    ],
    profile: {
      name: 'Student',
      university: '',
      semester: '',
      quoteEnabled: true,
    },
    settings: {
      focusDuration: 25,
      autoBreak: false,
      ambience: 'silent',
      notifications: true,
      deadlineAlerts: true,
      dailyBriefing: true,
      studyReminders: true,
    },
  };
}

const User = mongoose.model('User', UserSchema);

module.exports = {
  User,
  getDefaultState,
};
