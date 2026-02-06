const mongoose = require('mongoose');

const PdfAssetSchema = new mongoose.Schema({
  key: { type: String, default: '' },
  name: { type: String, default: '' },
  size: { type: Number, default: 0 },
  contentType: { type: String, default: '' },
  url: { type: String, default: '' },
  text: { type: String, default: '' },
  textUpdatedAt: { type: Date, default: null },
}, { _id: false });

const TaskSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, default: '' },
  dueDate: { type: String, default: '' },
  completed: { type: Boolean, default: false },
  subjectId: { type: String, default: '' },
  notes: { type: String, default: '' },
  pdfAttachment: { type: PdfAssetSchema, default: null },
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
  file: { type: PdfAssetSchema, default: null },
}, { _id: false });

const FolderSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, default: '' },
  parentId: { type: String, default: '' },
  items: { type: [FolderItemSchema], default: [] },
}, { _id: false });

// AI Reviewer Schemas
const MatchingPairSchema = new mongoose.Schema({
  id: { type: String, required: true },
  left: { type: String, default: '' },
  right: { type: String, default: '' },
}, { _id: false });

const ReviewerQuestionSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: { type: String, enum: ['identification', 'multiple_choice', 'true_false', 'word_matching'], required: true },
  question: { type: String, default: '' },
  options: { type: [String], default: [] },
  correctAnswer: { type: String, default: '' },
  pairs: { type: [MatchingPairSchema], default: [] },
}, { _id: false });

const QuizAttemptSchema = new mongoose.Schema({
  id: { type: String, required: true },
  score: { type: Number, default: 0 },
  totalQuestions: { type: Number, default: 0 },
  correctAnswers: { type: Number, default: 0 },
  timeTaken: { type: Number, default: 0 },
  completedAt: { type: String, default: '' },
}, { _id: false });

const AIReviewerSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, default: '' },
  sourceId: { type: String, default: '' },
  sourceFolderId: { type: String, default: '' },
  sourceName: { type: String, default: '' },
  difficulty: { type: String, enum: ['easy', 'medium', 'hard'], default: 'medium' },
  questionCount: { type: Number, default: 10 },
  questionMode: { type: String, enum: ['identification', 'multiple_choice', 'true_false', 'word_matching', 'hybrid'], default: 'hybrid' },
  timerMinutes: { type: Number, default: null },
  questions: { type: [ReviewerQuestionSchema], default: [] },
  createdAt: { type: String, default: '' },
  attempts: { type: [QuizAttemptSchema], default: [] },
  status: { type: String, enum: ['generating', 'ready', 'error'], default: 'generating' },
  errorMessage: { type: String, default: '' },
}, { _id: false });

const QuizProgressSchema = new mongoose.Schema({
  reviewerId: { type: String, default: '' },
  currentIndex: { type: Number, default: 0 },
  answers: { type: mongoose.Schema.Types.Mixed, default: {} },
  startedAt: { type: String, default: '' },
  timeRemaining: { type: Number, default: null },
}, { _id: false });

const AIChatMessageSchema = new mongoose.Schema({
  role: { type: String, enum: ['user', 'ai'], default: 'user' },
  text: { type: String, default: '' },
  refs: { type: [String], default: [] },
  createdAt: { type: String, default: '' },
}, { _id: false });

const UserProfileSchema = new mongoose.Schema({
  firstName: { type: String, default: 'Student' },
  lastName: { type: String, default: '' },
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

const NotificationMetaSchema = new mongoose.Schema({
  lastDailyBriefingAt: { type: Date, default: null },
  lastStudyReminderAt: { type: Date, default: null },
  pastDueNotifiedTasks: { type: [String], default: [] },
}, { _id: false });

const BillingSchema = new mongoose.Schema({
  plan: { type: String, enum: ['free', 'premium'], default: 'free' },
  interval: { type: String, enum: ['none', 'weekly', 'monthly', 'yearly'], default: 'none' },
  status: { type: String, enum: ['free', 'pending', 'active', 'canceled', 'expired', 'past_due'], default: 'free' },
  currentPeriodEnd: { type: Date, default: null },
  autoRenew: { type: Boolean, default: true },
  provider: { type: String, default: 'paymongo' },
  lastPaymentAt: { type: Date, default: null },
  pendingCheckoutId: { type: String, default: '' },
  pendingPlan: { type: String, default: '' },
  pendingInterval: { type: String, default: '' },
  // Track reviewer generations to prevent abuse (delete + recreate)
  reviewerGenerations: { type: [Date], default: [] },
  paymongo: {
    checkoutId: { type: String, default: '' },
    paymentId: { type: String, default: '' },
    paymentIntentId: { type: String, default: '' },
    sourceId: { type: String, default: '' },
    lastEventId: { type: String, default: '' },
    lastEventType: { type: String, default: '' },
  },
}, { _id: false });

// AI Usage Tracking Schema - prevents abuse and tracks costs
const AIUsageSchema = new mongoose.Schema({
  // Daily tracking (resets at UTC midnight)
  dailyCount: { type: Number, default: 0 },
  dailyResetDate: { type: String, default: '' }, // YYYY-MM-DD format
  
  // Monthly tracking (for analytics)
  monthlyCount: { type: Number, default: 0 },
  monthlyResetDate: { type: String, default: '' }, // YYYY-MM format
  
  // Rate limiting
  lastRequestAt: { type: Date, default: null },
  requestsThisMinute: { type: Number, default: 0 },
  minuteResetAt: { type: Date, default: null },
  
  // Free-tier cooldown (12-hour window)
  cooldownUntil: { type: Date, default: null },
  windowCount: { type: Number, default: 0 },
  windowStartedAt: { type: Date, default: null },
  
  // Lifetime stats
  totalRequests: { type: Number, default: 0 },
  totalChatRequests: { type: Number, default: 0 },
  totalReviewerRequests: { type: Number, default: 0 },
}, { _id: false });

const ZenStateSchema = new mongoose.Schema({
  tasks: { type: [TaskSchema], default: [] },
  subjects: { type: [SubjectSchema], default: [] },
  flashcards: { type: [FlashcardSchema], default: [] },
  folders: { type: [FolderSchema], default: [] },
  aiReviewers: { type: [AIReviewerSchema], default: [] },
  quizProgress: { type: QuizProgressSchema, default: null },
  aiChat: { type: [AIChatMessageSchema], default: [] },
  profile: { type: UserProfileSchema, default: () => ({}) },
  settings: { type: AppSettingsSchema, default: () => ({}) },
  updatedAt: { type: String, default: '' },
}, { _id: false });

const UserSchema = new mongoose.Schema({
  uid: { type: String, required: true, unique: true, index: true },
  email: { type: String, default: '' },
  state: { type: ZenStateSchema, default: () => getDefaultState() },
  notificationMeta: { type: NotificationMetaSchema, default: () => ({}) },
  billing: { type: BillingSchema, default: () => ({}) },
  aiUsage: { type: AIUsageSchema, default: () => ({}) },
}, { timestamps: true });

function getDefaultState() {
  return {
    tasks: [],
    subjects: [],
    flashcards: [],
    folders: [
      { id: 'general', name: 'General', items: [] },
    ],
    aiReviewers: [],
    quizProgress: null,
    aiChat: [],
    profile: {
      firstName: 'Student',
      lastName: '',
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
    updatedAt: new Date().toISOString(),
  };
}

const User = mongoose.model('User', UserSchema);

module.exports = {
  User,
  getDefaultState,
};
