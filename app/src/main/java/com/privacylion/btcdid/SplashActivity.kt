package com.privacylion.btcdid

import android.animation.ValueAnimator
import android.content.Intent
import android.graphics.*
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import androidx.activity.ComponentActivity

/**
 * Splash screen with animated cursive "S" handwriting effect.
 * The S draws itself elegantly, then transitions to the main app.
 */
class SplashActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val animatedView = AnimatedSignatureView(this)
        setContentView(animatedView)
        
        animatedView.startAnimation {
            // Animation complete, go to main activity
            startActivity(Intent(this, MainActivity::class.java))
            finish()
            // Fade transition
            overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
        }
    }
}

/**
 * Custom view that draws an animated cursive "S" with handwriting effect.
 */
class AnimatedSignatureView(context: android.content.Context) : View(context) {
    
    private val pathPaint = Paint().apply {
        color = Color.WHITE
        strokeWidth = 12f
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        isAntiAlias = true
    }
    
    private val glowPaint = Paint().apply {
        color = Color.WHITE
        strokeWidth = 20f
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        isAntiAlias = true
        maskFilter = BlurMaskFilter(15f, BlurMaskFilter.Blur.NORMAL)
        alpha = 100
    }
    
    private val gradientColors = intArrayOf(
        Color.parseColor("#3B82F6"),
        Color.parseColor("#8B5CF6")
    )
    
    private val sPath = Path()
    private val pathMeasure = PathMeasure()
    private val visiblePath = Path()
    private var pathLength = 0f
    private var animatedValue = 0f
    private var onComplete: (() -> Unit)? = null
    
    private var backgroundGradient: LinearGradient? = null
    private val backgroundPaint = Paint()
    
    init {
        // Disable hardware acceleration for blur effect
        setLayerType(LAYER_TYPE_SOFTWARE, null)
    }
    
    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        
        // Create background gradient
        backgroundGradient = LinearGradient(
            0f, 0f, w.toFloat(), h.toFloat(),
            gradientColors, null, Shader.TileMode.CLAMP
        )
        backgroundPaint.shader = backgroundGradient
        
        // Build the cursive S path centered on screen
        buildSignaturePath(w, h)
        
        pathMeasure.setPath(sPath, false)
        pathLength = pathMeasure.length
    }
    
    private fun buildSignaturePath(w: Int, h: Int) {
        val centerX = w / 2f
        val centerY = h / 2f
        val scale = minOf(w, h) / 4f
        
        sPath.reset()
        
        // Starting flourish (top right)
        sPath.moveTo(centerX + scale * 0.5f, centerY - scale * 0.9f)
        sPath.quadTo(
            centerX + scale * 0.3f, centerY - scale * 1.1f,
            centerX, centerY - scale * 0.8f
        )
        
        // Main S curve - top arc
        sPath.cubicTo(
            centerX - scale * 0.7f, centerY - scale * 0.8f,  // control 1
            centerX - scale * 0.6f, centerY - scale * 0.3f,  // control 2
            centerX, centerY                                   // end at center
        )
        
        // Main S curve - bottom arc
        sPath.cubicTo(
            centerX + scale * 0.6f, centerY + scale * 0.3f,  // control 1
            centerX + scale * 0.7f, centerY + scale * 0.8f,  // control 2
            centerX, centerY + scale * 0.8f                   // end
        )
        
        // Ending flourish (bottom left)
        sPath.quadTo(
            centerX - scale * 0.3f, centerY + scale * 1.1f,
            centerX - scale * 0.5f, centerY + scale * 0.9f
        )
    }
    
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        
        // Draw gradient background
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), backgroundPaint)
        
        // Draw the visible portion of the path
        visiblePath.reset()
        pathMeasure.getSegment(0f, pathLength * animatedValue, visiblePath, true)
        
        // Draw glow first
        canvas.drawPath(visiblePath, glowPaint)
        
        // Draw main stroke
        canvas.drawPath(visiblePath, pathPaint)
    }
    
    fun startAnimation(onComplete: () -> Unit) {
        this.onComplete = onComplete
        
        // Wait a moment before starting
        postDelayed({
            ValueAnimator.ofFloat(0f, 1f).apply {
                duration = 1200 // 1.2 seconds to draw
                interpolator = AccelerateDecelerateInterpolator()
                addUpdateListener { animation ->
                    animatedValue = animation.animatedValue as Float
                    invalidate()
                }
                addListener(object : android.animation.Animator.AnimatorListener {
                    override fun onAnimationStart(animation: android.animation.Animator) {}
                    override fun onAnimationCancel(animation: android.animation.Animator) {}
                    override fun onAnimationRepeat(animation: android.animation.Animator) {}
                    override fun onAnimationEnd(animation: android.animation.Animator) {
                        // Brief pause to admire, then continue
                        postDelayed({
                            this@AnimatedSignatureView.onComplete?.invoke()
                        }, 400)
                    }
                })
                start()
            }
        }, 200)
    }
}
